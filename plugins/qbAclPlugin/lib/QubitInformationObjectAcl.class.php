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
 * Custom ACL rules for QubitInformationObject resources
 *
 * @package    qbAclPlugin
 * @subpackage acl
 * @author     David Juhasz <david@artefactual.com>
 */
class QubitInformationObjectAcl extends QubitAcl
{
  // Add viewDraft and publish actions to list
  public static $ACTIONS = array(
    'read' => 'Read',
    'create' => 'Create',
    'update' => 'Update',
    'delete' => 'Delete',
    'translate' => 'Translate',
    'viewDraft' => 'View draft',
    'publish' => 'Publish',
    'readMaster' => 'Access master',
    'readReference' => 'Access reference',
    'readThumbnail' => 'Access thumbnail'
  );

  // For information objects check parent authorization for create OR publish
  // actions
  protected static $_parentAuthActions = ['create', 'publish'];

  public static function isAllowed($role, $resource, $action, $options = array())
  {
    if (!isset(class_implements($role)['Zend_Acl_Role_Interface']))
    {
      self::getInstance()->addRole($role);
    }

    // If attempting to read a draft information object, check viewDraft
    // permission as well as read permission
    if ('read' == $action)
    {
      if (null === $resource->getPublicationStatus())
      {
        throw new sfException(
          'No publication status set for information object id: '.$resource->id
        );
      }

      // If this is a draft information object
      if (
        QubitTerm::PUBLICATION_STATUS_DRAFT_ID
        == $resource->getPublicationStatus()->statusId
      )
      {
        $instance = self::getInstance()->buildAcl($resource, $options);

        // Authorize for read and viewDraft actions
        return
          $instance->acl->isAllowed($role, $resource, 'read')
          && $instance->acl->isAllowed($role, $resource, 'viewDraft');
      }
    }

    return parent::isAllowed($role, $resource, $action, $options);
  }
}
