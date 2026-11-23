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

class UserDeleteClipboardAction extends sfAction
{
    public function execute($request)
    {
        $this->resource = $this->getRoute()->resource;

        if (!isset($this->resource) || !$request->isMethod('post')) {
            $this->forward404();
        }

        // Except for administrators, only allow users to delete their own clipboards
        if (!$this->context->user->isAdministrator()) {
            if ($this->resource->id != $this->context->user->getAttribute('user_id')) {
                $this->redirect('admin/secure');
            }
        }

        $this->response->setHttpHeader('Content-Type', 'application/json; charset=utf-8');

        // Validates the CSRF token along with the clipboard ID
        $form = new sfForm();
        $form->setValidator('id', new sfValidatorString(['required' => true]));
        $form->bind($request->getPostParameters());

        if (!$form->isValid()) {
            $this->response->setStatusCode(400);

            return $this->renderText(json_encode(['error' => $this->context->i18n->__('Invalid request.')]));
        }

        $criteria = new Criteria();
        $criteria->add(QubitClipboardSave::USER_ID, $this->resource->id);
        $criteria->add(QubitClipboardSave::PASSWORD, $form->getValue('id'));
        $save = QubitClipboardSave::getOne($criteria);

        if (!isset($save)) {
            $this->response->setStatusCode(404);

            return $this->renderText(json_encode(['error' => $this->context->i18n->__('Clipboard ID not found.')]));
        }

        // Saved items are removed by the database's cascading foreign key
        $save->delete();

        return $this->renderText(json_encode([
            'success' => $this->context->i18n->__('Clipboard %1% deleted.', ['%1%' => $save->password]),
        ]));
    }
}
