from flask import Flask, request
from flask_restful import Resource, Api
from flask_jwt import JWT, jwt_required

from security import authenticate, identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'furqan'
api = Api(app)

jwt = JWT(app, authenticate, identity) # jwt creates a new end point. i.e. /auth
# when we call /auth we send it the username and password. 

items = []

class Item(Resource):
    @jwt_required()
    def get(self, name):
        # for item in items:
        #     if item['name'] == name:
        #         return item

        # instead of using for loop for filters in python, we can optimise this process by using lambda and filter function, builtin python. 

        # item = list(filter(lambda x: x["name"] == name, items))  
        # above line returns the list of matching item, not single item
        # for single item you can use next() keyword instead of list.
        item = next(filter(lambda x: x["name"] == name, items), None)
        # it gives us first item found by filter function. 
        # remember next can raise an error if there are no items left or found. so in order to avoid this we use ,None.

        return {"item" : item}, 200 if item else 404     

    def post(self, name):
        if next(filter(lambda x: x["name"] == name, items), None) is not None:
            return {"message": "An item with name '{}' already exists. ".format(name)}, 400
        data = request.get_json()
        item = {"name" : name, "price": data["price"]}
        items.append(item)
        return item, 201

class ItemList(Resource):
    def get(self):
        return {"items": items}


api.add_resource(Item, "/item/<string:name>")
api.add_resource(ItemList, "/items")

app.run(port=5000, debug=True)


















