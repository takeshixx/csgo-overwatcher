#!/usr/bin/env python3
import sys
import os
import re
import bz2
import requests
import subprocess
from scapy.all import *

RE_URL = re.compile(r'GET (/730/\d+_\d+.dem.bz2)')
RE_HOST = re.compile(r'Host: (replay\d+.valve.net)')
RE_FILENAME = re.compile(r'GET /730/(\d+_\d+.dem.bz2)')
RE_STEAMID = re.compile(r'STEAM_\d:\d:\d+')
TEAM_T = 2
TEAM_CT = 3
DEMOINFOGO = 'demoinfogo.exe'


def info(msg):
    print('[*] ' + str(msg))    
    

def warn(msg):
    print('[W] ' + str(msg))
    

def error(msg):
    print('[E] ' + str(msg))
    sys.exit(1)
    
    
def download_demo(url, filename):
    if (os.path.isfile(filename) and \
            os.path.getsize(filename) > 0) or \
            (os.path.isfile(filename) and \
            os.path.getsize(filename.replace('.bz2', '')) > 0):
        warn('Demo already loaded, skipping')
        return
    info('Downloading demo...')
    req = requests.get(url)
    with open(filename, 'wb') as f:
        f.write(req.content)
    info('Written demo as {}'.format(filename))
    if os.path.getsize(filename) > 0:
        decompress_demo(filename)
    else:
        warn('Demofile is too small, skipping.')
    

def decompress_demo(demofile):
    with open(demofile.replace('.bz2', ''), 'wb') as w:
        with open(demofile, 'rb') as r:
            w.write(bz2.decompress(r.read()))
    info('Decompressed demofile {}'.format(demofile))
    analyze_demo(demofile.replace('.bz2', ''))


def find_demo(pkt):
    p = str(pkt)
    url_matches = RE_URL.findall(p)
    host_matches = RE_HOST.findall(p)
    if url_matches and host_matches:
        url = 'http://{host}{url}'.format(
            host=host_matches[0],
            url=url_matches[0])
        info('Found new demo: {}'.format(url))
        filename = RE_FILENAME.findall(p)[0]
        download_demo(url, filename)
        
        
class Player(object):
    def __init__(self, xuid, name, userid, steamid=None):
        self.xuid = xuid
        self.name = name
        self.userid = userid
        self.steamid = steamid
        self.steamid64 = None
        if self.steamid != b'BOT':
            self.steamid64 = self.convert_to_steamid64(self.steamid)
        self.kills = 0
        self.deaths = 0
        self.assists = 0
        self.team = 0
        self.is_connected = False
        
    def __repr__(self):
        return self.__str__()
        
    def __str__(self):
        if not self.is_bot():
            return ('userID: {userid}, Name: {name}, Steam: {steam}, '
                    'SteamRep: {steamrep}, Kills: {kills}, Assists: '
                    '{assists}, Deaths: {deaths} ({xuid})').format(
                userid=self.userid.decode(),
                name=self.name.decode(),
                steam=self.get_steamcommunity_url(),
                steamrep=self.get_steamrep_url(),
                kills=self.kills,
                assists=self.assists,
                deaths=self.deaths,
                xuid=self.xuid.decode())
        else:
            return ('userID: {userid}, Name: {name}, Kills: {kills}, '
                    'Assists: {assists}, Deaths: {deaths}').format(
                userid=self.userid.decode(),
                name='BOT ' + self.name.decode(),
                kills=self.kills,
                assists=self.assists,
                deaths=self.deaths)
            
    def is_bot(self):
        return True if self.steamid == b'BOT' else False
        
    def convert_to_steamid64(self, steamid):
        if not steamid:
            return
        steam64id = 76561197960265728
        id_split = steamid.split(b':')
        steam64id += int(id_split[2]) * 2
        if id_split[1] == b'1':
            steam64id += 1
        return steam64id
        
    def get_steamcommunity_url(self):
        return 'https://steamcommunity.com/profiles/' + str(self.steamid64) if self.steamid64 else ''
       
    def get_steamrep_url(self):
        return 'https://steamrep.com/search?q=' + str(self.steamid64) if self.steamid64 else ''


class DemoInfo(object):
    def __init__(self, demofile):
        if not os.path.isfile(demofile) or \
            not os.path.getsize(demofile) > 0:
            error('Invalid demo file: ' + demofile)
        self.demofile = os.path.abspath(demofile)
        self.messages = {}
        self.players = {}
        self.current_round = 0
        self.ct_rounds_won = 0
        self.t_rounds_won = 0
        self.warmup_over = False
        
    def dump_demo(self):
        info('Start dumping demo...')
        # -stringtables is required to get 'player info'/player_info
        cmd_args = [DEMOINFOGO, '-gameevents', '-nofootsteps',
                    '-stringtables', '-nowarmup', self.demofile]
        p = subprocess.Popen(cmd_args, stdout=subprocess.PIPE)
        (output, error) = p.communicate()
        p_status = p.wait()
        if error:
            error('Running {} failed: {}'.format(DEMOINFOGO, error if error else 'Unknown error'))
        self.parse_demo_dump(output)
        
    def parse_demo_dump(self, dump):
        info('Parsing demo messages...')
        re_msg = re.compile(rb'(?:^|(?:\r)?\n)(\w+|(?:\w+\s+\w+))(?:\r)?\n{(?:\r)?\n (.*?)?(?:\r)?\n}', re.S | re.M)
        found_messages = re_msg.findall(dump)
        for msg in found_messages:
            message_type = msg[0].replace(b' ', b'_')
            message_data = msg[1]
            if not message_type in self.messages.keys():
                self.messages[message_type] = []
            message_data = self.parse_message_data(message_data)
            self.messages[message_type].append(message_data)
            self.handle_message(message_type, message_data)
        for playerid, player in self.players.items():
            print(player)
            print('---')

    def parse_message_data(self, data):
        return_dict = {}
        attributes = data.split(b'\r\n')
        for a in attributes:
            a = a.strip()
            try:
                key, val = a.split(b':', maxsplit=1)
                val = val.strip()
            except ValueError:
                key = a.split(b':')[0]
                val = None
            return_dict[key.strip()] = val
        return return_dict
        
    def handle_message(self, message_type, message_data):
        if message_type == b'player_info':
            if message_data[b'ishltv'] == b'1':
                return
            if not message_data[b'userID'] in self.players.keys():
                id_temp = self.player_get_id_for_xuid(message_data[b'xuid'])
                if id_temp:
                    # Players that reconnect get different userids?
                    self.players[id_temp].is_connected = True
                    self.players[id_temp].userid = message_data[b'userID']
                    self.players[message_data[b'userID']] = self.players[id_temp]
                    del self.players[id_temp]
                    return
                self.players[message_data[b'userID']] = Player(
                    message_data[b'xuid'],
                    message_data[b'name'],
                    message_data[b'userID'],
                    message_data[b'guid'])
                self.players[message_data[b'userID']].is_connected = True
            elif message_data[b'userID'] in self.players.keys() and message_data[b'updating'] == b'true':
                if self.players[message_data[b'userID']].xuid != message_data[b'xuid']:
                    warn('User not known, skipping stats recovery')
                    return
                new_player = Player(
                    message_data[b'xuid'],
                    message_data[b'name'],
                    message_data[b'userID'],
                    message_data[b'guid'])
                new_player.deaths = self.players[message_data[b'userID']].deaths
                new_player.kills = self.players[message_data[b'userID']].kills
                new_player.assists = self.players[message_data[b'userID']].assists
                del self.players[message_data[b'userID']]
                self.players[message_data[b'userID']] = new_player
        elif message_type == b'player_team':
            if message_data[b'disconnect'] == b'1' and message_data[b'isbot'] == b'0':
                self.players[self.parse_id_from_userid(message_data[b'userid'])].is_connected = False
            if message_data[b'disconnect'] == b'1' and message_data[b'isbot'] == b'1':
                # Remove a after after disconnect
                if self.parse_id_from_userid(message_data[b'userid']) in self.players.keys():
                    del self.players[self.parse_id_from_userid(message_data[b'userid'])]
        elif message_type == b'player_death':
            if not self.warmup_over:
                return
            if self.parse_id_from_userid(message_data[b'userid']) in self.players.keys():
                self.players[self.parse_id_from_userid(message_data[b'userid'])].deaths += 1
                if self.parse_id_from_userid(message_data[b'userid']) != self.parse_id_from_userid(message_data[b'attacker']):
                    # Kill was not a suicide
                    self.players[self.parse_id_from_userid(message_data[b'attacker'])].kills += 1
                if message_data[b'assister'] != b'0':
                    self.players[self.parse_id_from_userid(message_data[b'assister'])].assists += 1
        elif message_type == b'round_start':
            # lol why?!
            if message_data[b'timelimit'] == b'999':
                return
            self.warmup_over = True
            self.current_round += 1
        elif message_type == b'round_end':
            if message_data[b'winner'] == b'1':
                return
            if message_data[b'winner'] == b'3':
                self.ct_rounds_won += 1
            else:
                self.t_rounds_won += 1
            if self.current_round == 15:
                # Switch teams after halftime
                ct_temp = self.ct_rounds_won
                self.ct_rounds_won = self.t_rounds_won
                self.t_rounds_won = ct_temp
            self.print_stats(message_data)
            
    def print_stats(self, data):
        print('-- Player Stats - Round {total_rounds} - {current_winner}\'s won - [CT {ct_rounds}:{t_rounds} T] --'.format(
            total_rounds=self.current_round + 1,
            current_winner='CT' if data[b'winner'] == b'3' else 'T',
            ct_rounds=self.ct_rounds_won,
            t_rounds=self.t_rounds_won))
        padding = max(len(p.name) for _, p in self.players.items()) + 2
        for playerid, player in self.players.items():
            print('{} [ {}:{}:{} ]'.format(
                player.name.decode().ljust(padding) if not player.is_bot() else 'BOT ' + player.name.decode().ljust(padding),
                player.kills,
                player.assists,
                player.deaths))
        print("------------------")
        
    def parse_id_from_userid(self, userid):
        re_id = re.compile(rb'\s\(id:(\d{1,2})\)')
        ids = re_id.findall(userid)
        if ids:
            return ids[0]
        else:
            return userid
            
    def player_get_id_for_xuid(self, xuid):
        for playerid, player in self.players.items():
            if player.xuid == xuid:
                return playerid
        return False
 
def analyze_demo(filename):   
    demoinfo = DemoInfo(filename)
    demoinfo.dump_demo()
    
if __name__ == '__main__':
    demo_file = None
    if len(sys.argv) > 1:
        demo_file = sys.argv[1]
    if not demo_file:
        info('Sniffing for demo downloads...')
        sniff(filter='tcp port 80',prn=find_demo)
    else:
        analyze_demo(demo_file)
        