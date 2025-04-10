import graphene

class Query(graphene.ObjectType):
    hello = graphene.String(default_value="Hello, GraphQL in Django!")

schema = graphene.Schema(query=Query)
