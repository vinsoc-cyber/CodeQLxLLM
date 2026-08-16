def search(collection, name):
    return collection.find({"name": name})
