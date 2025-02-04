from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import current_app
from flask_restx import Resource, reqparse
from werkzeug.exceptions import *

import db.db_model as model
from db import db

# Parsers
login_parser = reqparse.RequestParser(bundle_errors=True)
login_parser.add_argument('username', type=str, help='Missing username', required=True)
login_parser.add_argument('password', type=str, help='Missing password', required=True)

user_parser = reqparse.RequestParser(bundle_errors=True)
user_parser.add_argument('username', type=str, required=False)
user_parser.add_argument('password', type=str, required=False)

idm_parser = reqparse.RequestParser(bundle_errors=True)
idm_parser.add_argument('name', type=str, help='Missing name', required=True)

token_parser = reqparse.RequestParser(bundle_errors=True)
token_parser.add_argument('Authorization', type=str, help='JWT token is missing', required=True, location=['cookies', 'headers'])

# Decorator to validate JWT token and user permission
def release_access(permission):
    def wrapper(func):
        def decorated(*args, **kwargs):
            args = token_parser.parse_args()
            token = args.get('Authorization').split(" ")[-1]

            user_token_data = jwt.decode(
                token,
                current_app.config['TOKEN_SECRET'],
                algorithms="HS256"
            )

            current_user = db.session.get(model.User, user_token_data["id"])

            if not current_user:
                return {"message": "User not found"}

            if permission:
                roles_from_group = user_token_data.get('roles') # Validate rules from JWT instead db

                if permission in roles_from_group:
                    return func(*args, **kwargs)

                return {"message": "Insufficient permissions"}

            return func(*args, **kwargs)
        return decorated
    return wrapper

def generate_token(user_id):
    user_entity = db.session.get(model.User, user_id)

    if not user_entity:
        return {"Message": "User not exist"}

    group_entity = db.paginate(
        db.select(model.UserAssignGroup).filter_by(user_id=user_entity.id)
    )

    group = ""
    roles = []
    if group_entity.items:
        group_id = group_entity.items[0].group_id

        group = db.session.get(model.Group, group_id).name

        roles = db.paginate(db.select(model.RoleAssignGroup).filter_by(group_id=group_id)).items

    token_payload = {
        "username": user_entity.username,
        "group": group,
        "roles": [role.role.name for role in roles],
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=30)
    }

    refresh_token_payload = {
        "id": user_entity.id,
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=60)
    }

    token_payload.update(refresh_token_payload)

    token = jwt.encode(
        token_payload,
        current_app.config['TOKEN_SECRET'],
        algorithm="HS256"
    )

    refresh_token = jwt.encode(
        refresh_token_payload,
        current_app.config['REFRESH_TOKEN_SECRET'],
        algorithm="HS256"
    )

    return {
        "token": token,
        "refresh_token": refresh_token
    }
    
class LoginResource(Resource):
    def post(self):
        args = login_parser.parse_args()
        username = args.get('username')
        password = args.get('password').encode(encoding="utf-8")

        user_entity = db.one_or_404(
            db.select(model.User).filter_by(username=username),
            description=f"User '{username}' not found"
        )

        if not user_entity and not bcrypt.checkpw(password, user_entity.password.encode(encoding="utf-8")):
            return {"message": "Username and password not match"}

        return generate_token(user_entity.id)

class RefreshTokenResource(Resource):
    def post(self):
        args = token_parser.parse_args()
        token = args.get('Authorization').split(" ")[-1]

        user_refresh_token_data = jwt.decode(
            token,
            current_app.config['REFRESH_TOKEN_SECRET'],
            algorithms="HS256"
        )

        return generate_token(user_refresh_token_data["id"])

class SignupResource(Resource):
    def post(self):
        args = login_parser.parse_args()

        username = args.get('username')
        password = args.get('password')

        user_entity = db.paginate(
            db.select(model.User).filter_by(username=username)
        )

        if user_entity.items:
            return {"message": "Username already exist"}

        hashed_password = bcrypt.hashpw(
            password.encode(encoding="utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        user = model.User(
            username = username,
            password = hashed_password,
        )

        db.session.add(user)
        db.session.commit()

        return {"message": "User created successfully"}
    
class UserResource(Resource):
    @release_access('adm-read')
    def get(self):
        user_entities = db.paginate(db.select(model.User))
        
        return {"users": [{"id": user.id, "username": user.username} for user in user_entities]}
    
    def patch(self, user_id: str = None):
        args = user_parser.parse_args()

        username = args.get('username')
        password = args.get('password')

        user_entity = db.session.get(model.User, user_id)

        if not user_entity:
            return {"message": "User id not found"}
        
        if username:
            validate_username = db.paginate(
                db.select(model.User).filter_by(username=username)
            )

            if validate_username.items:
                return {"message": "Username already exist"}
        
            user_entity.username = username

        if password:
            hashed_password = bcrypt.hashpw(
                password.encode(encoding="utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

            user_entity.password = hashed_password

        db.session.commit()

        return {"message": "User updated"}
    
    def delete(self, user_id: str = None):
        user = db.session.get(model.User, user_id)

        if not user:
            return {"message": "User id not found"}
        
        db.session.delete(user)
        db.session.commit()

        return {"message": "User deleted successfully"}
    
    @release_access('adm-user-role')
    def compound_user_group(self):
        user_entities = db.paginate(db.select(model.User))
        user_assign_group =  db.paginate(db.select(model.UserAssignGroup))

        return [
            {
                "id": user.id, 
                "username": user.username, 
                "group": next(filter(lambda group_user: group_user.user_id == user.id, user_assign_group.items)).group.name
            } for user in user_entities.items
        ]
        

class GroupResource(Resource):
    @release_access('adm-read')
    def get(self):
        group_entities = db.paginate(db.select(model.Group))

        return {"groups": [{"id": group.id, "group_name": group.name} for group in group_entities]}
    
    @release_access('adm-create')
    def post(self):
        args = idm_parser.parse_args()
        group_name = args.get("name")

        group_entity = db.paginate(
            db.select(model.Group).filter_by(name=group_name)
        )

        if group_entity.items:
            return {"message": "Group name already exist"}

        group = model.Group(
            name = group_name
        )

        db.session.add(group)
        db.session.commit()

        return {"message": "Group created successfully"}
    
    @release_access('adm-update')
    def put(self, group_id: str = None):
        args = idm_parser.parse_args()
        group_name = args.get("name")

        group_entity = db.paginate(
            db.select(model.Group).filter_by(name=group_name)
        )

        if group_entity.items and group_entity.items[0].id == int(group_id):
            return {"message": "Group already have this name"}
        
        if group_entity.items:
            return {"message": "Group name already exist"}

        current_group = db.session.get(model.Group, group_id)

        if not current_group:
            return {"message": "Group id not exist"}
 
        current_group.name = group_name

        db.session.commit()

        return {"message": "Group updated successfully"}

    @release_access('adm-delete')
    def delete(self, group_id: str = None):
        group_entity = db.session.get(model.Group, group_id)

        if not group_entity:
            return {"message": "Group id not exist"}
        
        db.session.delete(group_entity)
        db.session.commit()

        return {"message": "Group removed"}
    
    @release_access('adm-group-role')
    def compound_group_role(self):
        group_entities = db.paginate(db.select(model.Group))
        role_assign_group =  db.paginate(db.select(model.RoleAssignGroup))

        return [
            {
                "id": group.id, 
                "name": group.name, 
                "roles": [
                    item.role.name
                    for item in filter(lambda group_role: group_role.group_id == group.id, role_assign_group.items)
                ]
            } for group in group_entities.items
        ]

    
class RoleResource(Resource):
    @release_access('adm-read')
    def get(self):
        role_entities = db.paginate(db.select(model.Role))

        return {"roles": [{"id": role.id, "role_name": role.name} for role in role_entities]}

    @release_access('adm-create')
    def post(self):
        args = idm_parser.parse_args()
        role_name = args.get("name")

        role_entity = db.paginate(
            db.select(model.Role).filter_by(name=role_name)
        )

        if role_entity.items:
            return {"message": "Role name already exist"}

        role = model.Role(
            name = role_name
        )

        db.session.add(role)
        db.session.commit()

        return {"message": "Role created successfully"}

    @release_access('adm-update')
    def put(self, role_id: str = None):
        args = idm_parser.parse_args()
        role_name = args.get("name")

        role_entity = db.paginate(
            db.select(model.Role).filter_by(name=role_name)
        )

        if role_entity.items and role_entity.items[0].id == int(role_id):
            return {"message": "Role already have this name"}

        if role_entity.items:
            return {"message": "Role name already exist"}

        current_role = db.session.get(model.Role, role_id)

        if not current_role:
            return {"message": "Role id not exist"}

        current_role.name = role_name

        db.session.commit()

        return {"message": "Role updated successfully"}

    @release_access('adm-delete')
    def delete(self, role_id: str = None):
        role_entity = db.session.get(model.Role, role_id)

        if not role_entity:
            return {"message": "Role id not exist"}
        
        db.session.delete(role_entity)
        db.session.commit()

        return {"message": "Role removed"}

class UserAssignGroupResource(Resource):
    @release_access('adm-create')
    def post(self, group_id:str = None, user_id: str = None):
        group_entity = db.session.get(model.Group, group_id)
        user_entity = db.session.get(model.User, user_id)

        if not group_entity:
            return {"message": "Group id not exist"}
        
        if not user_entity:
            return {"message": "User id not exist"}
        
        user_in_user_assign_group = db.paginate(
            db.select(model.UserAssignGroup).filter_by(user_id=user_id)
        )

        if user_in_user_assign_group.items:
            return {"message": "User already assign to a group"}

        user_assign_group = model.UserAssignGroup(
            group_id = group_id,
            user_id = user_id
        )

        db.session.add(user_assign_group)
        db.session.commit()

        return {"message": "User assign to a group successfully"}

    @release_access('adm-update')
    def put(self, group_id:str = None, user_id: str = None):
        group_entity = db.session.get(model.Group, group_id)
        user_entity = db.session.get(model.User, user_id)

        if not group_entity:
            return {"message": "Group id not exist"}
        
        if not user_entity:
            return {"message": "User id not exist"}
        
        user_in_user_assign_group = db.paginate(
            db.select(model.UserAssignGroup).filter_by(user_id=user_id)
        )

        if not user_in_user_assign_group.items:
            return {"message": "User not assign to any group"}

        user_in_user_assign_group.items[0].group_id = group_id

        db.session.commit()

        return {"message": "User assign to new group"}

    @release_access('adm-delete')
    def delete(self, group_id:str = None, user_id: str = None):
        user_in_user_assign_group = db.paginate(
            db.select(model.UserAssignGroup).filter_by(user_id=user_id)
        )

        if not user_in_user_assign_group.items:
            return {"message": "User not assign to a group"}
        
        if user_in_user_assign_group.items[0].group_id != group_id:
            return {"message": "User not assign to this group"}

        db.session.delete(user_in_user_assign_group.items[0])
        db.session.commit()

        return {"message": "User is in none group"}


class RoleAssignGroupResource(Resource):
    @release_access('adm-create')
    def post(self, group_id:str = None, role_id: str = None):
        group_entity = db.session.get(model.Group, group_id)
        role_entity = db.session.get(model.Role, role_id)

        if not group_entity:
            return {"message": "Group id not exist"}

        if not role_entity:
            return {"message": "Role id not exist"}

        role_in_role_assign_group = db.paginate(
            db.select(model.RoleAssignGroup).filter_by(group_id=group_id, role_id=role_id)
        )

        if role_in_role_assign_group.items:
            return {"message": "Role already assign to this group"}

        role_assign_group = model.RoleAssignGroup(
            group_id = group_id,
            role_id = role_id
        )

        db.session.add(role_assign_group)
        db.session.commit()

        return {"message": "Role create successfully"}

    @release_access('adm-delete')
    def delete(self, group_id:str = None, role_id: str = None):
        role_in_role_assign_group = db.paginate(
            db.select(model.RoleAssignGroup).filter_by(group_id=group_id, role_id=role_id)
        )

        if not role_in_role_assign_group.items:
            return {"message": "Role not assign to this group"}

        db.session.delete(role_in_role_assign_group.items[0])
        db.session.commit()

        return {"message": "Role remove from this group"}
