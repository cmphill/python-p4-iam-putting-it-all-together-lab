#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        password_confirmation = data['password_confirmation']
        image_url = data['image_url']
        bio = data ['bio']

        if username and password==password_confirmation and image_url and bio :
            new_user = User(username=username)
            new_user.password_hash = password
            new_user.image_url = image_url
            new_user.bio = bio

            try:

                db.session.add(new_user)
                db.session.commit()

                session['user_id'] = new_user.id

                return new_user.to_dict(rules=('-_password_hash')), 201
            except IntegrityError:
                return {'error': '422 unprocessable entity'}, 422
        return {'error': '422 unprocessable entity'}, 422
class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()

            return user.to_dict(rules=('_password_hash')), 200
        
        return {'error': '401: not authorized'}, 401

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': '401 unauthorized'}, 401

class Logout(Resource):
    def delete(self):

        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        
        return {'error': '401 Unauthorized'}, 401
        
    

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()

            return [recipe.to_dict() for recipe in user.recipes], 200
        
        return {'error': '401 Unauthorized'}, 401
    
    def post(self):
        if session.get('user_id'):
            data = request.get_json()
            new_recipe = Recipe(
                title = data['title'],
                instructions = data['instructions'],
                minutes_to_complete = data['minutes_to_complete']
            )
            try:
                db.session.add(new_recipe)
                db.session.commit()

                return new_recipe.to_dict(), 201
            
            except:
                
                return {'error': '422 unprocessable'}, 422

        return {'error': '401 not authorized'}

        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
