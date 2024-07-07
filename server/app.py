#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.orm import Session
from config import app, db, api
from models import User
from sqlalchemy.exc import IntegrityError

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return {'error': 'Username and password required'}, 400

        user = User(username=username)
        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already taken'}, 400

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            with db.session() as db_session:
                user = db_session.get(User, user_id)
                if user:
                    return user.to_dict(), 200
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
            else:
                return {'error': 'Invalid password'}, 401
        else:
            return {'error': 'User not found'}, 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
