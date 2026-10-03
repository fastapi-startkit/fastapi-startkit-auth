from fastapi_startkit.masoniteorm.migrations import Migration


class CreateOauthClientsTable(Migration):
    async def up(self):
        async with await self.schema.create("oauth_clients") as table:
            table.string("id", 64).primary()
            table.string("name")
            table.string("secret").nullable()
            table.text("redirect_uris")
            table.boolean("confidential")
            table.text("grant_types")
            table.text("scopes")
            table.string("provider").nullable()
            table.text("owner_id").nullable()
            table.boolean("revoked")
            table.double("created_at")

    async def down(self):
        await self.schema.drop("oauth_clients")
