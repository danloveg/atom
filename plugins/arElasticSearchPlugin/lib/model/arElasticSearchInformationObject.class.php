<?php

/*
 * This file is part of the Access to Memory (AtoM) software.
 *
 * Access to Memory (AtoM) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Access to Memory (AtoM) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Access to Memory (AtoM).  If not, see <http://www.gnu.org/licenses/>.
 */

class arElasticSearchInformationObject extends arElasticSearchModelBase
{
    protected const NESTED_SET_PAGE_SIZE = 1000;
    protected static $conn;
    protected static $statement;
    protected static $counter = 0;

    protected $errors = [];

    public function load()
    {
        // Get count of all information objects
        $sql = 'SELECT COUNT(*)';
        $sql .= ' FROM '.QubitInformationObject::TABLE_NAME;
        $sql .= ' WHERE id > ?';

        $this->count = QubitPdo::fetchColumn($sql, [QubitInformationObject::ROOT_ID]);
    }

    public function populate()
    {
        $this->load();

        // Pass root data to top-levels to avoid ancestors query
        $ancestors = [[
            'id' => QubitInformationObject::ROOT_ID,
            'identifier' => null,
            'repository_id' => null,
        ]];

        // Walk the hierarchy in nested-set order. This avoids keeping large
        // sibling lists and recursive stack frames alive for the duration of a
        // deep branch.
        $this->addInformationObjectsByNestedSet(['ancestors' => $ancestors]);

        return $this->errors;
    }

    public function recursivelyAddInformationObjects($parentId, $totalRows, $options = [])
    {
        // Loop through children and add to search index
        foreach (self::getChildren($parentId) as $item) {
            $ancestors = $inheritedCreators = [];
            $repository = null;
            ++self::$counter;

            try {
                $node = new arElasticSearchInformationObjectPdo($item->id, $options);
                $data = $node->serialize();

                QubitSearch::getInstance()->addDocument($data, 'QubitInformationObject');

                $this->logEntry($data['i18n'][$data['sourceCulture']]['title'], self::$counter);

                $ancestors = array_merge($node->getAncestors(), [[
                    'id' => $node->id,
                    'identifier' => $node->identifier,
                    'repository_id' => $node->repository_id,
                ]]);
                $repository = $node->getRepository();
                $inheritedCreators = array_merge($node->inheritedCreators, $node->creators);
            } catch (sfException $e) {
                $this->errors[] = $e->getMessage();
            }

            unset($node, $data);
            $this->cleanupAfterInformationObject();

            // Descend hierarchy
            if (1 < ($item->rgt - $item->lft)) {
                // Pass ancestors, repository and creators down to descendants
                $this->recursivelyAddInformationObjects($item->id, $totalRows, [
                    'ancestors' => $ancestors,
                    'repository' => $repository,
                    'inheritedCreators' => $inheritedCreators,
                ]);
            }
        }
    }

    public static function update($object, $options = [])
    {
        // Update description
        $node = new arElasticSearchInformationObjectPdo($object->id);
        $serialized = $node->serialize();
        $updateDescendants = !empty($options['updateDescendants']) && $object->rgt - $object->lft > 1;
        $descendantOptions = $updateDescendants ? self::getDescendantOptions($node) : null;

        $qubitSearch = QubitSearch::getInstance();
        $qubitSearch->addDocument($serialized, 'QubitInformationObject');
        $qubitSearch->log(sprintf('    [%s] %d - "%s" inserted',
            str_replace('arElasticSearch', '', self::class),
            ++self::$counter,
            $serialized['i18n'][$serialized['sourceCulture']]['title']));

        unset($node, $serialized);

        // Update descendants if requested and they exists
        if ($updateDescendants) {
            self::updateDescendants($object, $descendantOptions);
        }
    }

    public static function updateDescendants($object, $options = null)
    {
        // Update synchronously in CLI tasks and jobs
        $context = sfContext::getInstance();
        $env = $context->getConfiguration()->getEnvironment();
        if (in_array($env, ['cli', 'worker'])) {
            if (null === $options) {
                $node = new arElasticSearchInformationObjectPdo($object->id);
                $options = self::getDescendantOptions($node);
                unset($node);
            }

            // TODO: Use partial updates to only get and add
            // the fields that are inherited from the ancestors.
            // Be aware that transient descendants are entirely
            // added the first time to the search index in here
            // and they will require a complete update.
            $indexer = new self();
            $indexer->addInformationObjectsByNestedSet($options, $object->lft, $object->rgt);

            return;
        }

        // Update asynchronously in other environments
        $jobOptions = [
            'ioIds' => [$object->id],
            'updateIos' => false,
            'updateDescendants' => true,
            'objectId' => $object->id,
        ];
        QubitJob::runJob('arUpdateEsIoDocumentsJob', $jobOptions);

        // Let user know descendants update has started
        $jobsUrl = $context->routing->generate(null, ['module' => 'jobs', 'action' => 'browse']);
        $message = $context->i18n->__('Your description has been updated. Its descendants are being updated asynchronously – check the <a class="alert-link" href="%1">job scheduler page</a> for status and details.', ['%1' => $jobsUrl]);
        $context->user->setFlash('notice', $message);
    }

    public static function getChildren($parentId)
    {
        if (!isset(self::$conn)) {
            self::$conn = Propel::getConnection();
        }

        if (!isset(self::$statement)) {
            $sql = 'SELECT io.id, io.lft, io.rgt';
            $sql .= ' FROM '.QubitInformationObject::TABLE_NAME.' io';
            $sql .= ' WHERE io.parent_id = ?';
            $sql .= ' ORDER BY io.lft';

            self::$statement = self::$conn->prepare($sql);
        }

        self::$statement->execute([$parentId]);

        return self::$statement->fetchAll(PDO::FETCH_OBJ);
    }

    protected function addInformationObjectsByNestedSet($options, $lft = null, $rgt = null)
    {
        $stack = [[
            'rgt' => $rgt ?: PHP_INT_MAX,
            'options' => $options,
        ]];
        $isSubtree = null !== $lft && null !== $rgt;
        $lastLft = $isSubtree ? $lft : 0;

        do {
            $statement = self::getNestedSetStatement($isSubtree);
            $statement->execute($isSubtree ? [$lastLft, $rgt] : [QubitInformationObject::ROOT_ID, $lastLft]);
            $rows = 0;

            while ($item = $statement->fetch(PDO::FETCH_OBJ)) {
                ++$rows;
                $lastLft = $item->lft;

                while (count($stack) > 1 && end($stack)['rgt'] < $item->lft) {
                    array_pop($stack);
                }

                ++self::$counter;
                $parent = end($stack);
                $childOptions = [
                    'ancestors' => [],
                    'repository' => null,
                    'inheritedCreators' => [],
                ];

                try {
                    $node = new arElasticSearchInformationObjectPdo($item->id, $parent['options']);
                    $data = $node->serialize();

                    QubitSearch::getInstance()->addDocument($data, 'QubitInformationObject');
                    $this->logIndexedInformationObject($data['i18n'][$data['sourceCulture']]['title']);

                    $childOptions = self::getDescendantOptions($node);
                } catch (sfException $e) {
                    $this->errors[] = $e->getMessage();
                }

                unset($node, $data, $parent);
                $this->cleanupAfterInformationObject();

                if (1 < ($item->rgt - $item->lft)) {
                    $stack[] = [
                        'rgt' => $item->rgt,
                        'options' => $childOptions,
                    ];
                }

                unset($childOptions);
            }

            $statement->closeCursor();
        } while (self::NESTED_SET_PAGE_SIZE == $rows);

        unset($stack);
    }

    protected static function getNestedSetStatement($isSubtree)
    {
        if (!isset(self::$conn)) {
            self::$conn = Propel::getConnection();
        }

        if ($isSubtree) {
            $sql = 'SELECT io.id, io.lft, io.rgt';
            $sql .= ' FROM '.QubitInformationObject::TABLE_NAME.' io';
            $sql .= ' WHERE io.lft > ? AND io.rgt < ?';
            $sql .= ' ORDER BY io.lft';
            $sql .= ' LIMIT '.self::NESTED_SET_PAGE_SIZE;

            return self::$conn->prepare($sql);
        }

        $sql = 'SELECT io.id, io.lft, io.rgt';
        $sql .= ' FROM '.QubitInformationObject::TABLE_NAME.' io';
        $sql .= ' WHERE io.id > ? AND io.lft > ?';
        $sql .= ' ORDER BY io.lft';
        $sql .= ' LIMIT '.self::NESTED_SET_PAGE_SIZE;

        return self::$conn->prepare($sql);
    }

    protected static function getDescendantOptions($node)
    {
        return [
            'ancestors' => array_merge($node->getAncestors(), [[
                'id' => $node->id,
                'identifier' => $node->identifier,
                'repository_id' => $node->repository_id,
            ]]),
            'repository' => $node->getRepository(),
            'inheritedCreators' => array_merge($node->inheritedCreators, $node->creators),
        ];
    }

    protected function cleanupAfterInformationObject()
    {
        if (0 != self::$counter % 100) {
            return;
        }

        Qubit::clearClassCaches();

        if (function_exists('gc_collect_cycles')) {
            gc_collect_cycles();
        }
    }

    protected function logIndexedInformationObject($title)
    {
        if (isset($this->timer)) {
            $this->logEntry($title, self::$counter);

            return;
        }

        QubitSearch::getInstance()->log(sprintf('    [%s] %d - "%s" inserted',
            str_replace('arElasticSearch', '', self::class),
            self::$counter,
            $title));
    }
}
