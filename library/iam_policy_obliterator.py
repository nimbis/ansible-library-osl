#!/usr/bin/python
# This file is part of Nimbis' installation of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

EXAMPLES = """
- name: Obliterate policies for Groups
  iam_policy_obliterator:
    iam_type: "group"
    iam_name: "Devops"
    state: "absent"
    spare: "{{ iam_groups.devops.policies }}"
"""

try:
    import boto
    import boto.iam
    import boto.ec2
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def boto_exception(err):
    '''generic error message handler'''
    if hasattr(err, 'error_message'):
        error = err.error_message
    elif hasattr(err, 'message'):
        error = err.message
    else:
        error = '%s: %s' % (Exception, err)

    return error


def user_action(module, iam, name, state, spare):
    changed = False
    try:
        current_policies = [
            cp for cp in
            iam.get_all_user_policies(name).
            list_user_policies_result.
            policy_names]
        spare_list = [s['name'] for s in spare]
        kill_list = [p for p in current_policies if p not in spare_list]
        for policy_name in kill_list:
            try:
                iam.delete_user_policy(name, policy_name)
                changed |= True
            except boto.exception.BotoServerError as err:
                error_msg = boto_exception(err)
                if 'cannot be found.' in error_msg:
                    changed |= False
                    module.exit_json(
                        changed=changed,
                        msg="%s policy is already absent" % policy_name)

        updated_policies = [
            cp for cp in
            iam.get_all_user_policies(name).
            list_user_policies_result.
            policy_names]

    except boto.exception.BotoServerError as err:
        error_msg = boto_exception(err)
        module.fail_json(changed=changed, msg=error_msg)

    return changed, name, updated_policies


def role_action(module, iam, name, state, spare):
    changed = False
    try:
        current_policies = [
            cp for cp in iam.list_role_policies(name).
            list_role_policies_result.
            policy_names]

        spare_list = [s['name'] for s in spare]
        kill_list = [p for p in current_policies if p not in spare_list]
        for policy_name in kill_list:
            try:
                iam.delete_role_policy(name, policy_name)
                changed |= True
            except boto.exception.BotoServerError as err:
                error_msg = boto_exception(err)
                if 'cannot be found.' in error_msg:
                    changed |= False
                    module.exit_json(
                        changed=changed,
                        msg="%s policy is already absent" % policy_name)
                else:
                    module.fail_json(msg=err.message)

        updated_policies = [
            cp for cp in iam.list_role_policies(name).
            list_role_policies_result.
            policy_names]

    except boto.exception.BotoServerError as err:
        error_msg = boto_exception(err)
        module.fail_json(changed=changed, msg=error_msg)

    return changed, name, updated_policies


def group_action(module, iam, name, state, spare):
    changed = False
    msg = ''
    try:
        current_policies = [
            cp for cp in
            iam.get_all_group_policies(name).
            list_group_policies_result.
            policy_names]

        spare_list = [s['name'] for s in spare]
        kill_list = [p for p in current_policies if p not in spare_list]
        for policy_name in kill_list:
            try:
                iam.delete_group_policy(name, policy_name)
                changed |= True
            except boto.exception.BotoServerError as err:
                error_msg = boto_exception(err)
                if 'cannot be found.' in error_msg:
                    changed |= False
                    module.exit_json(
                        changed=changed,
                        msg="%s policy is already absent" % policy_name)

        updated_policies = [
            cp for cp in iam.get_all_group_policies(name).
            list_group_policies_result.
            policy_names]

    except boto.exception.BotoServerError as err:
        error_msg = boto_exception(err)
        module.fail_json(changed=changed, msg=error_msg)

    return changed, name, updated_policies, msg


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        iam_type=dict(
            default=None, required=True, choices=['user', 'group', 'role']),
        # Call me odd, but I want to know this is their intent.
        state=dict(default=None, required=True, choices=['absent']),
        iam_name=dict(default=None, required=False),
        spare=dict(type='list', required=True)
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    state = module.params.get('state').lower()
    iam_type = module.params.get('iam_type').lower()
    name = module.params.get('iam_name')
    spare = module.params.get('spare')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module)

    try:
        if region:
                iam = connect_to_aws(boto.iam, region, **aws_connect_kwargs)
        else:
                iam = boto.iam.connection.IAMConnection(**aws_connect_kwargs)
    except boto.exception.NoAuthHandlerFound as e:
            module.fail_json(msg=str(e))

    changed = False

    if iam_type == 'user':
        changed, user_name, current_policies = user_action(
            module, iam, name, state, spare)
        module.exit_json(
            changed=changed,
            user_name=name,
            policies=current_policies)
    elif iam_type == 'role':
        changed, role_name, current_policies = role_action(
            module, iam, name, state, spare)
        module.exit_json(
            changed=changed,
            role_name=name,
            policies=current_policies)
    elif iam_type == 'group':
        changed, group_name, current_policies, msg = group_action(
            module, iam, name, state, spare)
        module.exit_json(
            changed=changed,
            group_name=name,
            policies=current_policies,
            msg=msg)

from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *  # noqa


main()
