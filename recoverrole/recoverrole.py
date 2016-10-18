import discord
from discord.ext import commands
from cogs.utils.dataIO import dataIO
import logging
from .utils import checks
from __main__ import send_cmd_help
import os
log = logging.getLogger('red.recoverrole')


class Recover_role:
    """Allows the user to recover a previous role"""

    # --- Format
    # {
    # Server : {
    #   Toggle: True/False
    #   User : {
    #       Roles :
    #       }
    #    }
    # }
    # ---
    def __init__(self, bot):
        self.bot = bot
        self.json = {}
        self.location = 'data/recover_role/settings.json'
        self.json = dataIO.load_json(self.location)

    def _get_server_from_id(self, serverid):
        return discord.utils.get(self.bot.servers, id=serverid)

    def _get_role_from_id(self, serverid, roleid):
        server = self._get_server_from_id(serverid)
        try:
            roles = server.roles
        except AttributeError:
            raise RoleNotFound(server, roleid)
        return discord.utils.get(roles, id=roleid)

    @commands.command(pass_context=True, no_pm=True)
    async def recoverrole(self, ctx):
        """Recover your previous roles."""
        server = ctx.message.server.id
        author = ctx.message.author
        if server not in self.json:
            await self.bot.say(':warning: RecoverRole isn\'t setup yet. Please ask your admin to set it up.')
        elif self.json[server]['toggle'] is False:
            await self.bot.say(':warning: RecoverRole is disabled on this server. Ye cannot get ye flask.')
        else:
            if author.id in self.json[server]:
                await self.bot.say('Are you sure you want to recover these role?\nType *"Yes"* to confirm.')
                log.debug('USER({}) has requested a role recovery'.format(author.id))
                answer = await self.bot.wait_for_message(timeout=30, author=author)
                if answer is None:
                    await self.bot.say(':warning: {}, you didn\'t respond in time.'.format(author.display_name))
                    log.debug('USER({}) failed to respond to recover roles.'.format(author.id))
                elif 'yes' in answer.content.lower() and author.id in self.json[server]:
                    try:
                        for thing in self.json[server][author.id]['roles']:
                            await self.bot.add_roles(author, self._get_role_from_id(server, thing))
                        await self.bot.say(':white_check_mark: Your roles have been recovered.')
                        log.debug('USER({}) successfully recovered roles.'.format(author.id))
                    except discord.Forbidden:
                        await self.bot.say(":warning: Discord told me I cannot recover that role.")
                else:
                    await self.bot.say(':warning: That wasn\'t a yes, {}. Oh well.'.format(author.display_name))
            else:
                await self.bot.say(':warning: {}, you have no roles to recover.'.format(author.display_name))

    @commands.group(pass_context=True, no_pm=True)
    @checks.admin_or_permissions(administrator=True)
    async def recoverroleset(self, ctx):
        """Manage the settings for RecoverRole"""
        server = ctx.message.server.id
        if server not in self.json:  # Setup the 'server' block in in the dict
            self.json[server] = {'toggle': True}
            dataIO.save_json(self.location, self.json)
            log.debug('Wrote server ID({})'.format(server))
        if ctx.invoked_subcommand is None:
            await send_cmd_help(ctx)

    @recoverroleset.command(pass_context=True, no_pm=True)
    async def info(self, ctx):
        """Displays your current roles in the recovery table."""
        server = ctx.message.server.id
        author = ctx.message.author
        if author.id in self.json[server]:
            role_ids = self.json[server][author.id]['roles']
            users_roles = []
            for thing in role_ids:
                users_roles.append(self._get_role_from_id(server, thing))
            await self.bot.say(':white_check_mark: Your stored roles are: {}'.format(users_roles))

    @recoverroleset.command(pass_context=True, no_pm=True)
    async def add(self, ctx):
        """Adds your current roles to the recovery table."""
        server = ctx.message.server.id
        author = ctx.message.author
        existing_roles = []
        for thing in author.roles:
            if thing.name != "@everyone":
                existing_roles.append(thing.id)
        self.json[server][author.id] = {'roles': existing_roles}
        dataIO.save_json(self.location, self.json)
        log.debug('Wrote ROLES({}) for USER({}) from SERVER({})'.format(existing_roles, author.display_name, server))
        await self.bot.say(':white_check_mark: Added {} to the recovery list for {}.'.format(author.roles, author.display_name))

    @recoverroleset.command(hidden=True, pass_context=True, no_pm=True)
    async def removeme(self, ctx):
        """Removes yourself from the recovery table. This hidden command is dangerous!"""
        server = ctx.message.server.id
        author = ctx.message.author
        try:
            del self.json[server][author.id]
            dataIO.save_json(self.location, self.json)
            log.debug('Removed USER({}) from SERVER({})'.format(author.id, server))
            await self.bot.say(':white_check_mark: You have been removed from the role recovery list.')
        except:
            await self.bot.say(':warning: {} isn\'t in the role recovery list.'.format(author.display_name))

    @recoverroleset.command(pass_context=True, no_pm=True)
    @checks.admin_or_permissions(administrator=True)
    async def toggle(self, ctx):
        """Enables or disables recovering roles in the server"""
        server = ctx.message.server.id
        if self.json[server]['toggle'] is True:
            self.json[server]['toggle'] = False
            await self.bot.say(':white_check_mark: Toggle disabled! You can no longer recover roles on this server.')
        else:
            self.json[server]['toggle'] = True
            await self.bot.say(':white_check_mark: Toggle enabled! You can now recover roles on this server.')
        log.debug('Wrote toggle to {} in server ID({})'.format(self.json[server]['toggle'], server))
        dataIO.save_json(self.location, self.json)

    @recoverroleset.command(hidden=True, pass_context=True)
    @checks.admin_or_permissions(administrator=True)
    async def dumprecoverycore(self, ctx):
        """Debug Code"""
        await self.bot.say('```\n{}```'.format(self.json))

    @recoverroleset.command(hidden=True, pass_context=True)
    @checks.admin_or_permissions(administrator=True)
    async def dumpmyroles(self, ctx):
        """Debug Code"""
        author = ctx.message.author
        for thing in author.roles:
            if thing.name != "@everyone":
                await self.bot.say(':white_check_mark: You are a ROLE({0.name}) with ID({0.id})'.format(thing))

    @recoverroleset.command(hidden=True, pass_context=True)
    @checks.admin_or_permissions(administrator=True)
    async def dumpserverroles(self, ctx):
        """Debug Code"""
        await self.bot.say('Server roles available:')
        for thing in ctx.message.server.roles:
            if thing.name != "@everyone":
                await self.bot.say(':white_check_mark: Server ROLE({0.name}) with ID({0.id})'.format(thing))

    async def _update_name(self, old, new):  # Change the 'name' variable in the role ID.
        if new.server.id in self.json:
            if old.name != new.name:
                if new.id in self.json[new.server.id]:
                    self.json[new.server.id][new.id]['name'] = new.name
                    log.debug('Written new name to {}'.format(new.id))
                    dataIO.save_json(self.location, self.json)


def check_folder():
    if not os.path.exists('data/recover_role'):
        log.debug('Creating folder: data/recover_role')
        os.makedirs('data/recover_role')


def check_file():
    f = 'data/recover_role/settings.json'
    if dataIO.is_valid_json(f) is False:
        log.debug('Creating json: settings.json')
        dataIO.save_json(f, {})


def setup(bot):
    check_folder()
    check_file()
    n = Recover_role(bot)
    bot.add_listener(n._update_name, 'on_server_role_update')
    bot.add_cog(n)
