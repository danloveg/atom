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

class UserClipboardsAction extends sfAction
{
    public function execute($request)
    {
        $this->resource = $this->getRoute()->resource;
        $this->abortInvalidRequests();

        // Criteria to fetch clipboards saved by the user
        $criteria = new Criteria();
        $criteria->add(QubitClipboardSave::USER_ID, $this->resource->id);
        $criteria->addDescendingOrderByColumn(QubitClipboardSave::CREATED_AT);
        $criteria->addDescendingOrderByColumn(QubitClipboardSave::ID);

        // Page results
        $limit = sfConfig::get('app_hits_per_page');
        $page = (isset($request->page) && ctype_digit($request->page)) ? $request->page : 1;

        $pager = new QubitPager('QubitClipboardSave');
        $pager->setCriteria($criteria);
        $pager->setPage($page);
        $pager->setMaxPerPage($limit);

        // Return results and paging data
        $data = [
            'results' => $this->summarizeCurrentPage($pager),
            'items' => $pager->getNbResults(),
            'pages' => $pager->getLastPage(),
        ];

        $this->response->setHttpHeader('Content-Type', 'application/json; charset=utf-8');

        return $this->renderText(json_encode($data));
    }

    private function abortInvalidRequests()
    {
        if (!isset($this->resource)) {
            $this->forward404();
        }

        // Except for administrators, only allow users to see their own profile
        if (!$this->context->user->isAdministrator()) {
            if ($this->resource->id != $this->context->user->getAttribute('user_id')) {
                $this->redirect('admin/secure');
            }
        }
    }

    private function summarizeCurrentPage($pager)
    {
        $saves = [];
        foreach ($pager->getResults() as $save) {
            $saves[] = $save;
        }

        if (empty($saves)) {
            return [];
        }

        $dateFormatter = new sfDateFormat($this->context->user->getCulture());
        $loadUrl = $this->context->routing->generate(null, ['module' => 'clipboard', 'action' => 'load']);
        $counts = $this->getItemCounts($saves);

        $results = [];

        foreach ($saves as $save) {
            $results[] = [
                'password' => $save->password,
                'createdAt' => $dateFormatter->format($save->createdAt, 'f'),
                'loadUrl' => $loadUrl.'?id='.rawurlencode($save->password),
                'counts' => $counts[$save->id] ?? [],
            ];
        }

        return $results;
    }

    // Count the items in each saved clipboard, grouped by entity type
    private function getItemCounts($saves)
    {
        $labels = [
            'QubitInformationObject' => sfConfig::get('app_ui_label_informationobject'),
            'QubitActor' => sfConfig::get('app_ui_label_actor'),
            'QubitRepository' => sfConfig::get('app_ui_label_repository'),
            'QubitAccession' => sfConfig::get('app_ui_label_accession', $this->context->i18n->__('Accession')),
        ];

        $ids = [];
        foreach ($saves as $save) {
            $ids[] = $save->id;
        }

        $sql = sprintf(
            'SELECT save_id, item_class_name, COUNT(*) AS count
            FROM clipboard_save_item
            WHERE save_id IN (%s)
            GROUP BY save_id, item_class_name
            ORDER BY save_id, item_class_name',
            implode(',', array_fill(0, count($ids), '?'))
        );

        $counts = [];

        foreach (QubitPdo::fetchAll($sql, $ids) as $row) {
            $counts[$row->save_id][] = [
                'type' => $labels[$row->item_class_name] ?? str_replace('Qubit', '', $row->item_class_name),
                'count' => (int) $row->count,
            ];
        }

        return $counts;
    }
}
