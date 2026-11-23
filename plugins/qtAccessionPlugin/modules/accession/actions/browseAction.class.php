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

class AccessionBrowseAction extends DefaultBrowseAction
{
    // Should be able to search specifically on:
    // - accessionNumber
    // - sourceOfAcquisition
    // - locationInformation
    // - acquisitionType (QubitTerm) ACCESSION_ACQUISITION_TYPE_ID = 63;
    // - resourceType (QubitTerm) ACCESSION_RESOURCE_TYPE_ID = 62;
    // - title
    // - creator
    // - archivalHistory
    // - scopeAndContent
    // - appraisal
    // - physicalCondition
    // - receivedExtent
    // - processingStatus (QubitTerm) ACCESSION_PROCESSING_STATUS_ID = 65;
    // - processingPriority (QubitTerm) ACCESSION_PROCESSING_PRIORITY_ID = 64;
    // - processingNotes

    // The name of each input field in the advanced search form
    // These all get rendered under "Limit results to:"
    public static $NAMES = [
        // Whether accession record is an accrual to another accession record or not
        'isAccrual',
        // Whether accession record has a deaccession record or not
        'hasDeaccession',
        // Whether archival descriptions have been linked or not
        'hasArchivalDescription',
        // The name of the donor (QubitDonor)
        'donor',
        // Start date of Acquisition
        'acqusitionStartDate',
        // End date of Acquisition
        'acquisitionEndDate',
        // Option for "Exact" or "Overlapping" dates
        'rangeType',
    ];

    // Removable filter tags for search criteria
    public static $FILTERTAGS = [
        'isAccrual' => [],
        'hasDeaccession' => [],
        'hasArchivalDescription' => [],
        'donor' => ['model' => 'QubitDonor'],
        'dateRange' => ['params' => ['startDate', 'endDate'], 'operator' => 'or'],
        'acquisitionType' => ['model' => 'QubitTerm'], // ACCESSION_ACQUISITION_TYPE_ID = 63;
        'resourceType' => ['model' => 'QubitTerm'], // ACCESSION_RESOURCE_TYPE_ID = 62;
        'processingStatus' => ['model' => 'QubitTerm'], // ACCESSION_PROCESSING_STATUS_ID = 65;
        'processingPriority' => ['model' => 'QubitTerm'], // ACCESSION_PROCESSING_PRIORITY_ID = 64;
    ];

    public static $AGGS = [
        'acquisitionType' => [
            'type' => 'term',
            'field' => 'acquisitionType.id',
            'size' => 10,
        ],
        'resourceType' => [
            'type' => 'term',
            'field' => 'resourceType.id',
            'size' => 10,
        ],
        'processingStatus' => [
            'type' => 'term',
            'field' => 'processingStatus.id',
            'size' => 10,
        ],
        'processingPriority' => [
            'type' => 'term',
            'field' => 'processingPriority.id',
            'size' => 10,
        ],
        'donor' => [
            'type' => 'term',
            'field' => 'donors.id',
            'size' => 10,
        ],
        'creator' => [
            'type' => 'term',
            'field' => 'creators.id',
            'size' => 10,
        ],
    ];

    public function execute($request)
    {
        // Translate field labels
        $this->i18n = $this->context->i18n;

        // TODO: Not sure what this should be, yet.
        $this->fieldOptions = [];

        // If a global search has been requested, translate that into an advanced search
        if (isset($request->subquery)) {
            $request->sq0 = $request->subquery;
        }

        // Add first criterion to the search box if it's over any field
        if (1 !== preg_match('/^[\s\t\r\n]*$/', $request->sq0) && !isset($request->sf0)) {
            $request->subquery = $request->sq0;
        }

        // Create the query and filter it with the selected aggs
        parent::execute($request);

        $this->setFilterTags($request);
        $this->addHiddenFields($request);
        $this->setForm($request);

        // Do the search
        $resultSet = $this->doSearch($request);

        $this->pager = new QubitSearchPager($resultSet);
        $this->pager->setPage($request->page ?: 1);
        $this->pager->setMaxPerPage($this->limit);
        $this->pager->init();

        $this->populateAggs($resultSet);

        $this->showAdvanced = filter_var(
            $request->showAdvanced,
            FILTER_VALIDATE_BOOLEAN
        );
    }

    /**
     * Set sort order based on requested ordering.
     *
     * Modifies $this->search in-place.
     *
     * @param mixed $request
     */
    protected function setSort($request)
    {
        switch ($request->sort) {
            case 'identifier': // For backward compatibility
            case 'accessionNumber':
                $this->search->query->setSort(['identifier.untouched' => $request->sortDir]);

                break;

            case 'title':
            case 'alphabetic': // For backward compatibility
                $field = sprintf('i18n.%s.title.alphasort', $this->context->user->getCulture());
                $this->search->query->addSort([$field => $request->sortDir]);

                break;

            case 'acquisitionDate':
                $this->search->query->addSort(['date' => ['order' => $request->sortDir, 'missing' => '_last']]);

                break;

            case 'relevance':
                // Keep boost options
                break;

            case 'lastUpdated':
            default:
                $this->search->query->setSort(['updatedAt' => $request->sortDir]);

                break;
        }
    }

    protected function setFilterTags($request)
    {
        $this->populateFilterTags($request);

        // Override label for accrual status
        if (filter_var($request->isAccrual, FILTER_VALIDATE_BOOLEAN)) {
            $this->setFilterTagLabel('isAccrual', $this->i18n->__('Is an accrual'));
        } elseif ('0' === $request->isAccrual) {
            $this->setFilterTagLabel('isAccrual', $this->i18n->__('Is not an accrual'));
        } else {
            unset($request->isAccrual);
        }

        // Override label for deaccession status
        if (filter_var($request->hasDeaccession, FILTER_VALIDATE_BOOLEAN)) {
            $this->setFilterTagLabel('hasDeaccession', $this->i18n->__('With deaccession'));
        } elseif ('0' === $request->hasDeaccession) {
            $this->setFilterTagLabel('hasDeaccession', $this->i18n->__('With no deaccession'));
        } else {
            unset($request->hasDeaccession);
        }

        // Override label for archival description status
        if (filter_var($request->hasArchivalDescription, FILTER_VALIDATE_BOOLEAN)) {
            $this->setFilterTagLabel('hasArchivalDescription', $this->i18n->__('With archival description'));
        } elseif ('0' === $request->hasArchivalDescription) {
            $this->setFilterTagLabel('hasArchivalDescription', $this->i18n->__('Without archival description'));
        } else {
            unset($request->hasArchivalDescription);
        }
    }

    protected function addHiddenFields($request)
    {
        // Keep control of which hidden fields are added to avoid
        // Cross-Site Scripting vulnerability. Only allow:
        // - Aggregations
        // - Sort options
        // TODO: ??
        $allowed = array_merge(
            array_keys($this::$AGGS),
            ['sort', 'sortDir'],
        );

        // TODO: What should the ignored fields be?
        // From actor module: These get relayed as form field default values (?)
        // From informationobject module: But ignore aggs already included in the form: (?)
        $ignored = ['repository', 'entityType', 'relatedType', 'relatedAuthority'];

        $this->setHiddenFields($request, $allowed, $ignored);
    }

    /**
     * Create a new form for the advanced search functionality.
     *
     * Adds a form field for every field in $NAMES.
     *
     * @param $request The request that triggered this action
     */
    protected function setForm($request)
    {
        $this->form = new sfForm([], [], false);
        $this->form->getValidatorSchema()->setOption('allow_extra_fields', true);

        foreach ($this::$NAMES as $name) {
            $this->addField($name, $request);
        }
    }

    /**
     * Add a new field to the form. Modifies $this->form in-place.
     *
     * @param $name    The name of the field. Should be a name in $NAMES
     * @param $request The request that triggered this action
     */
    protected function addField($name, $request)
    {
        switch ($name) {
            default:
                // TODO: Do something!
                break;
        }
    }

    /**
     * Execute the search based on the search term.
     *
     * @param $request The request that triggered this action
     */
    protected function doSearch($request)
    {
        $this->setSort($request);

        $this->search->addAdvancedSearchFilters($this::$NAMES + array_keys($this->fieldOptions), $request->getParameterHolder()->getAll(), 'accession');

        $this->search->query->setQuery($this->search->queryBool);

        return QubitSearch::getInstance()
            ->index
            ->getIndex('QubitAccession')
            ->search($this->search->getQuery(false));
    }

    /**
     * Implement aggregations for fields in $AGGS.
     *
     * @param $name    The name of the aggregation field. Should be a name in $AGGS
     * @param $buckets The aggregation "buckets" to be filled with values to filter by
     */
    protected function populateAgg($name, $buckets)
    {
        switch ($name) {
            case 'acquisitionType':
            case 'resourceType':
            case 'processingStatus':
            case 'processingPriority':
                $ids = array_column($buckets, 'key');
                $criteria = new Criteria();
                $criteria->add(QubitTerm::ID, $ids, Criteria::IN);

                foreach (QubitTerm::get($criteria) as $item) {
                    $buckets[array_search($item->id, $ids)]['display'] = $item->getName(['cultureFallback' => true]);
                }

                break;

            case 'donor':
                $ids = array_column($buckets, 'key');
                $criteria = new Criteria();
                $criteria->add(QubitDonor::ID, $ids, Criteria::IN);

                foreach (QubitDonor::get($criteria) as $item) {
                    $buckets[array_search($item->id, $ids)]['display'] = $item->__toString();
                }

                break;

            case 'creator':
                $ids = array_column($buckets, 'key');
                $criteria = new Criteria();
                $criteria->add(QubitActor::ID, $ids, Criteria::IN);

                foreach (QubitActor::get($criteria) as $item) {
                    $buckets[array_search($item->id, $ids)]['display'] = $item->__toString();
                }

                break;

            default:
                return parent::populateAgg($name, $buckets);
        }

        return $buckets;
    }
}
