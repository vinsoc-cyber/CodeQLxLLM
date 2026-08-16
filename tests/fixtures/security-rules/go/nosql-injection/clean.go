package main

import "go.mongodb.org/mongo-driver/bson"

func q(name string) bson.M { return bson.M{"name": name} }
