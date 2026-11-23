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

/**
 * Serialize accession objects in search index.
 *
 * @author     Daniel Lovegrove <d.lovegrove11@gmail.com>
 */
class arElasticSearchAccessionPdo
{
    protected static $conn;
    protected static $statements;
    protected $data = [];
    protected $events = [];

    public function __construct($id, $options = [])
    {
        if (isset($options['conn'])) {
            self::$conn = $options['conn'];
        }

        if (!isset(self::$conn)) {
            self::$conn = Propel::getConnection();
        }

        $this->loadData($id, $options);
    }

    public function __isset($name)
    {
        if ('events' == $name) {
            return isset($this->events);
        }

        return isset($this->data[$name]);
    }

    public function __get($name)
    {
        if ('events' == $name) {
            return $this->events;
        }

        if (isset($this->data[$name])) {
            return $this->data[$name];
        }
    }

    public function __set($name, $value)
    {
        if ('events' == $name) {
            $this->events = $value;

            return;
        }

        $this->data[$name] = $value;
    }

    public function serialize()
    {
        $serialized = [];
        $serialized['id'] = $this->id;
        $serialized['slug'] = $this->slug;
        $serialized['identifier'] = $this->identifier;
        $serialized['date'] = arElasticSearchPluginUtil::convertDate($this->date);
        $serialized['createdAt'] = arElasticSearchPluginUtil::convertDate($this->created_at);
        $serialized['updatedAt'] = arElasticSearchPluginUtil::convertDate($this->updated_at);
        $serialized['sourceCulture'] = $this->source_culture;
        $serialized['i18n'] = arElasticSearchModelBase::serializeI18ns($this->id, ['QubitAccession']);

        $alternativeIdentifiers = $this->getSerializedAlternativeIdentifiers();
        if (count($alternativeIdentifiers) > 0) {
            $serialized['alternativeIdentifiers'] = $alternativeIdentifiers;
        }

        $donors = $this->getSerializedDonors();
        if (count($donors) > 0) {
            $serialized['donors'] = $donors;
        }

        $creators = $this->getSerializedCreators();
        if (count($creators) > 0) {
            $serialized['creators'] = $creators;
        }

        if (count($this->events) > 0) {
            $serialized['accessionEvents'] = $this->events;
        }

        $propertyTermMapping = [
            'acquisition_type_id' => 'acquisitionType',
            'processing_priority_id' => 'processingPriority',
            'processing_status_id' => 'processingStatus',
            'resource_type_id' => 'resourceType',
        ];

        // Serialize linked terms
        foreach ($propertyTermMapping as $property => $serializedName) {
            if (empty($this->{$property})) {
                continue;
            }

            $node = new arElasticSearchTermPdo($this->{$property});
            $serialized[$serializedName] = $node->serialize();
        }

        return $serialized;
    }

    public function loadData($id, $options)
    {
        if (!isset(self::$statements['accession'])) {
            $sql = 'SELECT acc.*, slug.slug
                FROM '.QubitAccession::TABLE_NAME.' acc
                JOIN '.QubitSlug::TABLE_NAME.' slug ON acc.id = slug.object_id
                WHERE acc.id = :id';

            self::$statements['accession'] = self::$conn->prepare($sql);
        }

        self::$statements['accession']->execute([':id' => $id]);
        $this->data = self::$statements['accession']->fetch(PDO::FETCH_ASSOC);

        if (false === $this->data) {
            throw new sfException("Couldn't find accession (id: {$id})");
        }

        $this->loadAccessionEvents();

        return $this;
    }

    protected function loadAccessionEvents()
    {
        if (!isset(self::$statements['event'])) {
            $sql = 'SELECT
                event.id,
                event.type_id,
                event.date,
                note.id AS note_id
                FROM '.QubitAccessionEvent::TABLE_NAME.' event
                INNER JOIN '.QubitNote::TABLE_NAME.' note
                ON (event.id=note.object_id AND note.type_id=?)
                WHERE event.accession_id = ?';

            self::$statements['event'] = self::$conn->prepare($sql);
        }

        self::$statements['event']->execute([QubitTerm::ACCESSION_EVENT_NOTE_ID, $this->id]);

        foreach (self::$statements['event']->fetchAll(PDO::FETCH_ASSOC) as $item) {
            $event = ['id' => $item['id']];

            $event['date'] = arElasticSearchPluginUtil::normalizeDateWithoutMonthOrDay($item['date']);
            $event['dateString'] = Qubit::renderDate($item['date']);

            // Serialize type term
            if ($item['type_id']) {
                $event['type'] = ['i18n' => arElasticSearchModelBase::serializeI18ns(
                    $item['type_id'],
                    ['QubitTerm'],
                    ['fields' => ['name']]
                )];
            }

            // Serialize note
            if ($item['note_id']) {
                $event['notes'] = ['i18n' => arElasticSearchModelBase::serializeI18ns(
                    $item['note_id'],
                    ['QubitNote'],
                    ['fields' => ['content']]
                )];
            }

            // Serialize accession event i18n data
            $event['i18n'] = arElasticSearchModelBase::serializeI18ns($item['id'], ['QubitAccessionEvent']);

            $this->events[] = $event;
        }

        return $this->events;
    }

    protected function getSerializedAlternativeIdentifiers()
    {
        $sql = 'SELECT o.id, o.source_culture, o.type_id FROM '.QubitOtherName::TABLE_NAME.' o
            INNER JOIN '.QubitTerm::TABLE_NAME.' t ON o.type_id=t.id
            WHERE o.object_id = ? AND t.taxonomy_id= ?';

        $params = [$this->id, QubitTaxonomy::ACCESSION_ALTERNATIVE_IDENTIFIER_TYPE_ID];

        $alternativeIdentifiers = [];

        foreach (QubitPdo::fetchAll($sql, $params) as $item) {
            $alternativeIdentifiers[] = arElasticSearchOtherName::serialize($item);
        }

        return $alternativeIdentifiers;
    }

    protected function getSerializedDonors()
    {
        $donors = [];
        foreach (QubitRelation::getRelationsBySubjectId($this->id, ['typeId' => QubitTerm::DONOR_ID]) as $item) {
            $donors[] = arElasticSearchDonor::serialize($item->object);
        }

        return $donors;
    }

    protected function getSerializedCreators()
    {
        $creators = [];
        foreach (QubitRelation::getRelationsByObjectId($this->id, ['typeId' => QubitTerm::CREATION_ID]) as $item) {
            $node = new arElasticSearchActorPdo($item->subject->id);

            $serializedCreator = [
                'id' => $node->id,
                'i18n' => arElasticSearchModelBase::serializeI18ns(
                    $node->id,
                    ['QubitActor'],
                    ['fields' => ['authorized_form_of_name']]
                ),
            ];

            // Add other names, parallel names, and standardized names
            $serializedCreator += $node->serializeAltNames();

            $creators[] = $serializedCreator;
        }

        return $creators;
    }
}
