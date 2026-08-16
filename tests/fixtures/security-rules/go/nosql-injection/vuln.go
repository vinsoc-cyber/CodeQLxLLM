package main

import "go.mongodb.org/mongo-driver/bson"

func q(userJS string) bson.M { return bson.M{"$where": userJS} }
