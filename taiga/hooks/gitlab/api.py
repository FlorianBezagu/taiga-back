# Copyright (C) 2014 Andrey Antukh <niwi@niwi.be>
# Copyright (C) 2014 Jesús Espino <jespinog@gmail.com>
# Copyright (C) 2014 David Barragán <bameda@dbarragan.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from rest_framework.response import Response
from django.utils.translation import ugettext_lazy as _

from taiga.base.api.viewsets import GenericViewSet
from taiga.base import exceptions as exc
from taiga.base.utils import json
from taiga.projects.models import Project

from . import event_hooks
from .exceptions import ActionSyntaxException

import hmac
import hashlib


class GitLabViewSet(GenericViewSet):
    # We don't want rest framework to parse the request body and transform it in
    # a dict in request.DATA, we need it raw
    parser_classes = ()

    # This dict associates the event names we are listening for
    # with their reponsible classes (extending event_hooks.BaseEventHook)
    event_hook_classes = {
        "push": event_hooks.PushEventHook,
        "issue": event_hooks.IssuesEventHook,
    }

    def _validate_signature(self, project, request):
        secret_key = request.GET.get("key", None)

        if secret_key is None:
            return False

        if not hasattr(project, "modules_config"):
            return False

        if project.modules_config.config is None:
            return False

        project_secret = project.modules_config.config.get("gitlab", {}).get("secret", "")
        if not project_secret:
            return False

        return project_secret == secret_key

    def _get_project(self, request):
        project_id = request.GET.get("project", None)
        try:
            project = Project.objects.get(id=project_id)
            return project
        except Project.DoesNotExist:
            return None

    def _get_event_name(self, request):
        payload = json.loads(request.body.decode("utf-8"))
        return payload.get('object_kind', 'push')

    def create(self, request, *args, **kwargs):
        project = self._get_project(request)
        if not project:
            raise exc.BadRequest(_("The project doesn't exist"))

        try:
            payload = json.loads(request.body.decode("utf-8"))
        except ValueError:
            raise exc.BadRequest(_("The payload is not a valid json"))

        event_name = self._get_event_name(request)

        if not self._validate_signature(project, request):
            raise exc.BadRequest(_("Bad signature"))

        event_hook_class = self.event_hook_classes.get(event_name, None)
        if event_hook_class is not None:
            event_hook = event_hook_class(project, payload)
            try:
                event_hook.process_event()
            except ActionSyntaxException as e:
                raise exc.BadRequest(e)

        return Response({})
