from fastapi_startkit.masoniteorm.migrations import Migration


class AddFamilyIdToOauthRefreshTokensTable(Migration):
    async def up(self):
        async with await self.schema.table("oauth_refresh_tokens") as table:
            table.string("family_id", 64).nullable()
            table.index("family_id")

    async def down(self):
        async with await self.schema.table("oauth_refresh_tokens") as table:
            table.drop_index(["family_id"])
            table.drop_column("family_id")
