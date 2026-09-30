from fastapi_startkit.masoniteorm.migrations import Migration


class CreatePersonalApiTokensTable(Migration):
    async def up(self):
        async with await self.schema.create("personal_api_tokens") as table:
            table.string("id").primary()
            table.text("user_id").nullable()
            table.string("token_hash")
            table.string("name").nullable()
            table.text("abilities")
            table.double("last_used_at").nullable()
            table.double("expires_at").nullable()
            table.double("created_at")
            table.index("user_id")

    async def down(self):
        await self.schema.drop("personal_api_tokens")
