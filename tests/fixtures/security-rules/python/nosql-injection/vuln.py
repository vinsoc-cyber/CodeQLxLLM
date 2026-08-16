def search(collection, name):
    return collection.find({"$where": "this.name == '" + name + "'"})
