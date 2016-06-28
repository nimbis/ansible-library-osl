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
- name: Obliterate IAM Groups
  iam_obliterator:
    path: "/nimbis-admin/"
    iam_type: "group"
    state: "absent"
    spare: "Devops"
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


def _paginate(func, attr, **kwargs):
    '''
    paginates the results from func by continuously passing in
    the returned marker if the results were truncated. this returns
    an iterator over the items in the returned response. `attr` is
    the name of the attribute to iterate over in the response.
    '''
    finished, marker = False, None
    while not finished:
        res = func(marker=marker, **kwargs)
        for item in getattr(res, attr):
            yield item

        finished = res.is_truncated == 'false'
        if not finished:
            marker = res.marker


def list_all_groups(iam, **kwargs):
    return [
        item['group_name']
        for item
        in _paginate(iam.get_all_groups, 'groups', **kwargs)]


def list_all_users(iam, **kwargs):
    return [
        item['user_name']
        for item
        in _paginate(iam.get_all_users, 'users', **kwargs)]


def list_all_roles(iam, **kwargs):
    return [
        item['role_name']
        for item
        in _paginate(iam.list_roles, 'roles', **kwargs)]


def list_all_instance_profiles(iam, **kwargs):
    return [
        item['instance_profile_name']
        for item
        in _paginate(
            iam.list_instance_profiles, 'instance_profiles', **kwargs)]

def set_users_groups(module, iam, name, groups, updated=None, new_name=None):
    """
    Sets groups for a user, will purge groups not explictly passed, while
    retaining pre-existing groups that also are in the new list.
    """
    changed = False

    if updated:
        name = new_name

    try:
        orig_users_groups = [
            og['group_name']
            for og in
            iam.get_groups_for_user(name).list_groups_for_user_result.groups]
        remove_groups = [
            rg for rg in frozenset(orig_users_groups).difference(groups)]
    except boto.exception.BotoServerError as err:
        module.fail_json(changed=changed, msg=str(err))
    else:
        if len(orig_users_groups) > 0:
            for rm in remove_groups:
                iam.remove_user_from_group(rm, name)


    if len(remove_groups) > 0 or len(new_groups) > 0:
        changed = True

    return (groups, changed)

def delete_user(module, iam, name):
    del_meta = ''
    try:
        current_keys = [
            ck['access_key_id'] for ck in
            iam.get_all_access_keys(name).
            list_access_keys_result.
            access_key_metadata]
        # Must delete all keys first.
        for key in current_keys:
            iam.delete_access_key(key, name)
        # Must delete policies first.
        for policy in (iam.get_all_user_policies(name).

                       list_user_policies_result.
                       policy_names):
            iam.delete_user_policy(name, policy)
        try:
            iam.get_login_profiles(name).get_login_profile_response
        except boto.exception.BotoServerError as err:
            error_msg = boto_exception(err)
            if ('Cannot find Login Profile') in error_msg:
                del_meta = iam.delete_user(name).delete_user_response
        else:
            iam.delete_login_profile(name)
            del_meta = iam.delete_user(name).delete_user_response
    except Exception as ex:
        module.fail_json(changed=False, msg="delete failed %s" % ex)
        if ('must detach all policies first') in error_msg:
            for policy in (iam.get_all_user_policies(name).
                           list_user_policies_result.
                           policy_names):
                iam.delete_user_policy(name, policy)
            try:
                del_meta = iam.delete_user(name)
            except boto.exception.BotoServerError as err:
                error_msg = boto_exception(err)
                if ('must detach all policies first') in error_msg:
                    module.fail_json(
                        changed=changed,
                        msg=(
                            "All inline polices have been removed. Though it "
                            "appears that %s has Managed Polices. This is not "
                            "currently supported by boto. Please detach the "
                            "polices through the console and try again." % name
                        ))
                else:
                    module.fail_json(changed=changed, msg=str(error_msg))
            else:
                changed = True
                return del_meta, name, changed
    else:
        changed = True
        return del_meta, name, changed


def delete_group(module=None, iam=None, name=None, path='/nimbis-admin/'):
    changed = False
    try:
        # Must get rid of policies first...
        for policy in (iam.get_all_group_policies(name).
                       list_group_policies_result.policy_names):
            iam.delete_group_policy(name, policy)
        # ... and then group memebers
        for user in [u['user_name'] for u in iam.get_group(name).users]:
            iam.remove_user_from_group(name, user)
        iam.delete_group(name)
    except boto.exception.BotoServerError as err:
        module.fail_json(changed=changed, msg=str(err))
    else:
        changed = True
    return changed, name


def delete_role(
        module, iam, name, role_list, prof_list, path='/nimbis-admin/'):
    changed = False
    iam_role_result = None
    instance_profile_result = None
    try:
        if name in role_list:
            cur_ins_prof = [rp['instance_profile_name'] for rp in
                            iam.list_instance_profiles_for_role(name).
                            list_instance_profiles_for_role_result.
                            instance_profiles]
            # Must get rid of profiles first.
            for profile in cur_ins_prof:
                iam.remove_role_from_instance_profile(profile, name)
            # Must get rid of policies first.
            for policy in (iam.list_role_policies(name).
                           list_role_policies_result.policy_names):
                iam.delete_role_policy(name, policy)
            try:
                iam.delete_role(name)
            except boto.exception.BotoServerError as err:
                error_msg = boto_exception(err)
                try:
                    iam_role_result = iam.delete_role(name)
                except boto.exception.BotoServerError as err:
                    error_msg = boto_exception(err)
                    if ('must detach all policies first') in error_msg:
                        msg = (
                            "All inline polices have been removed. Though it "
                            "appears that %s has Managed Polices. This is not "
                            "currently supported by boto. Please detach the "
                            "polices  through the console and try again."
                            % name)
                        module.fail_json(changed=changed, msg=msg)
                    else:
                        module.fail_json(changed=changed, msg=str(err))
                else:
                    changed = True

            else:
                changed = True

        for prof in prof_list:
            if name == prof:
                instance_profile_result = iam.delete_instance_profile(name)
    except boto.exception.BotoServerError as err:
        module.fail_json(changed=changed, msg=str(err))
    else:
        updated_role_list = list_all_roles(iam, path_prefix=path)
    return changed, updated_role_list, iam_role_result, instance_profile_result


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        iam_type=dict(
            default=None, required=True, choices=['user', 'group', 'role']),
        spare=dict(type='list', default=None, required=True),
        # Call me odd, but I want to know this is their intent.
        state=dict(
            default=None, required=True, choices=['absent']),
        path=dict(required=True),
    )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['trust_policy', 'trust_policy_filepath']],
    )

    if not HAS_BOTO:
        module.fail_json(msg='This module requires boto, please install it')

    iam_type = module.params.get('iam_type').lower()
    spare = module.params.get('spare')
    path = module.params.get('path')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module)

    try:
        if region:
            iam = connect_to_aws(boto.iam, region, **aws_connect_kwargs)
        else:
            iam = boto.iam.connection.IAMConnection(**aws_connect_kwargs)
    except boto.exception.NoAuthHandlerFound as e:
        module.fail_json(msg=str(e))

    changed = False

    try:
        orig_group_list = list_all_groups(iam, path_prefix=path)

        orig_user_list = list_all_users(iam, path_prefix=path)

        orig_role_list = list_all_roles(iam, path_prefix=path)

        orig_prof_list = list_all_instance_profiles(iam, path_prefix=path)
    except boto.exception.BotoServerError as err:
        module.fail_json(msg=err.message)

    if iam_type == 'user':
        spare_list = [s['name'] for s in spare]
        kill_list = [u for u in orig_user_list if u not in spare_list]
        removed_users = []
        try:
            for name in kill_list:
                set_users_groups(module, iam, name, [])
                del_meta, name, changed = delete_user(module, iam, name)
                removed_users.append(name)
            module.exit_json(deleted_users=removed_users, changed=changed)

        except Exception as ex:
            module.fail_json(changed=changed, msg=str(ex))

    elif iam_type == 'group':
        spare_list = [s['name'] for s in spare]
        kill_list = [g for g in orig_group_list if g not in spare_list]
        removed_groups = []
        for name in kill_list:
            one_changed, removed_group = delete_group(
                iam=iam, name=name, path=path)
            changed |= one_changed
            removed_groups.append(removed_group)
        module.exit_json(changed=changed, delete_groups=removed_groups)

    elif iam_type == 'role':
        role_list = []
        role_result = None
        instance_profile_result = {}
        spare_list = [s['name'] for s in spare]
        kill_list = [r for r in orig_role_list if r not in spare_list]
        for name in kill_list:
            (one_changed, role_list,
             role_result, instance_profile_result) = delete_role(
                module, iam, name, orig_role_list, orig_prof_list, path=path)
            changed |= one_changed
        module.exit_json(
            changed=changed, roles=role_list, role_result=role_result,
            instance_profile_result=instance_profile_result)

from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.ec2 import *  # noqa

main()
