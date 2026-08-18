import discord
import aiohttp
import ipaddress
import re
import os
import socket
import asyncio
import json
import hashlib
from discord.ext import commands
from discord import app_commands

# Load configuration
def load_config():
    config_file = "config.json"
    default_config = {
        "prefix": "S",
        "intelx_api_key": "",
        "alienvault_api_key": "",
        "color_scheme": {
            "ip_lookup": 3447003,
            "asn_lookup": 10038562,
            "subnet_lookup": 65280,
            "reverse_dns": 9699539,
            "dns_lookup": 16753920,
            "whois_lookup": 16766976,
            "nmap_scan": 10038562,
            "port_scan": 16753920,
            "url_scan": 5898240,
            "intelx_lookup": 15158332,
            "malware_scan": 15418782
        }
    }
    
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    else:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

config = load_config()

# Set up the bot with necessary intents
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=config.get("prefix", "S"), intents=intents)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    print(f'Command Prefix: {config.get("prefix", "S")}')
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Error syncing commands: {e}")

def get_color(command_type):
    """Get color for embed based on command type"""
    colors = config.get("color_scheme", {})
    return colors.get(command_type, discord.Color.blurple().value)

# IP lookup command
@bot.tree.command(name="iplookup", description="Lookup information about an IP address")
@app_commands.describe(ip_address="The IP address to lookup")
async def ip_lookup(interaction: discord.Interaction, ip_address: str):
    await interaction.response.defer()
    
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        embed = discord.Embed(
            title="❌ Invalid Input",
            description=f"Invalid IP address: {ip_address}",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('status') == 'success':
                        embed = discord.Embed(
                            title="IP Lookup Results",
                            color=get_color("ip_lookup")
                        )
                        embed.set_author(name="Venice OSINT")
                        embed.add_field(name="🌍 Country", value=data.get('country', 'N/A'), inline=True)
                        embed.add_field(name="🏙️ Region", value=data.get('regionName', 'N/A'), inline=True)
                        embed.add_field(name="🏢 City", value=data.get('city', 'N/A'), inline=True)
                        embed.add_field(name="🌐 ISP", value=data.get('isp', 'N/A'), inline=True)
                        embed.add_field(name="🏭 Organization", value=data.get('org', 'N/A'), inline=True)
                        embed.add_field(name="🕐 Timezone", value=data.get('timezone', 'N/A'), inline=True)
                        embed.add_field(name="📍 Lat/Lon", value=f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}", inline=True)
                        embed.add_field(name="📮 Zip Code", value=data.get('zip', 'N/A'), inline=True)
                        embed.add_field(name="🚫 VPN/Proxy", value="Yes" if data.get('proxy', False) else "No", inline=True)
                        embed.set_footer(text=f"Venice OSINT | Query: {ip_address}")
                        
                        await interaction.followup.send(embed=embed)
                    else:
                        embed = discord.Embed(
                            title="❌ Error",
                            description=data.get('message', 'Unknown error'),
                            color=discord.Color.red()
                        )
                        embed.set_author(name="Venice OSINT")
                        await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# ASN lookup command
@bot.tree.command(name="asnlookup", description="Lookup ASN information for an IP address")
@app_commands.describe(ip_address="The IP address to lookup ASN")
async def asn_lookup(interaction: discord.Interaction, ip_address: str):
    await interaction.response.defer()
    
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        embed = discord.Embed(
            title="❌ Invalid Input",
            description=f"Invalid IP address: {ip_address}",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('status') == 'success':
                        embed = discord.Embed(
                            title="ASN Lookup Results",
                            color=get_color("asn_lookup")
                        )
                        embed.set_author(name="Venice OSINT")
                        embed.add_field(name="🏷️ ASN", value=data.get('as', 'N/A'), inline=True)
                        embed.add_field(name="🌐 ISP", value=data.get('isp', 'N/A'), inline=True)
                        embed.add_field(name="🏭 Organization", value=data.get('org', 'N/A'), inline=True)
                        embed.add_field(name="📅 Allocated", value=data.get('date', 'N/A'), inline=True)
                        embed.set_footer(text=f"Venice OSINT | Query: {ip_address}")
                        
                        await interaction.followup.send(embed=embed)
                    else:
                        embed = discord.Embed(
                            title="❌ Error",
                            description=data.get('message', 'Unknown error'),
                            color=discord.Color.red()
                        )
                        embed.set_author(name="Venice OSINT")
                        await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Subnet lookup command
@bot.tree.command(name="subnetlookup", description="Lookup information about a subnet")
@app_commands.describe(subnet="The subnet to lookup (e.g., 192.168.1.0/24)")
async def subnet_lookup(interaction: discord.Interaction, subnet: str):
    await interaction.response.defer()
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        embed = discord.Embed(
            title="❌ Invalid Input",
            description=f"Invalid subnet format: {subnet}",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        netmask = network.netmask
        wildcard = ipaddress.IPv4Address(~int(netmask) & 0xFFFFFFFF)
        
        embed = discord.Embed(
            title="Subnet Information",
            color=get_color("subnet_lookup")
        )
        embed.set_author(name="Venice OSINT")
        embed.add_field(name="📡 Network Address", value=str(network.network_address), inline=True)
        embed.add_field(name="📻 Broadcast Address", value=str(network.broadcast_address), inline=True)
        embed.add_field(name="🔒 Netmask", value=str(netmask), inline=True)
        embed.add_field(name="🎯 Wildcard Mask", value=str(wildcard), inline=True)
        embed.add_field(name="🔢 Total IPs", value=str(network.num_addresses), inline=True)
        embed.add_field(name="👥 Usable IPs", value=str(network.num_addresses - 2) if network.num_addresses > 2 else "0", inline=True)
        embed.add_field(name="🔖 Prefix", value=str(network.prefixlen), inline=True)
        
        if network.num_addresses > 2:
            first_usable = str(network.network_address + 1)
            last_usable = str(network.broadcast_address - 1)
            embed.add_field(name="🚀 First Usable", value=first_usable, inline=True)
            embed.add_field(name="🏁 Last Usable", value=last_usable, inline=True)
        
        embed.set_footer(text=f"Venice OSINT | Query: {subnet}")
        
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Reverse DNS lookup command
@bot.tree.command(name="reversedns", description="Lookup reverse DNS information for an IP address")
@app_commands.describe(ip_address="The IP address to reverse lookup")
async def reverse_dns(interaction: discord.Interaction, ip_address: str):
    await interaction.response.defer()
    
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        embed = discord.Embed(
            title="❌ Invalid Input",
            description=f"Invalid IP address: {ip_address}",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip_address)
        
        embed = discord.Embed(
            title="Reverse DNS Lookup",
            color=get_color("reverse_dns")
        )
        embed.set_author(name="Venice OSINT")
        embed.add_field(name="🌐 IP Address", value=ip_address, inline=True)
        embed.add_field(name="🔗 Hostname", value=hostname, inline=True)
        embed.set_footer(text=f"Venice OSINT | Query: {ip_address}")
        
        await interaction.followup.send(embed=embed)
    except socket.herror:
        embed = discord.Embed(
            title="❌ No Record Found",
            description=f"No reverse DNS record found for {ip_address}",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# DNS lookup command
@bot.tree.command(name="dnslookup", description="Lookup DNS records for a domain")
@app_commands.describe(domain="The domain to lookup (e.g., example.com)")
async def dns_lookup(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    
    try:
        url = f"https://dns.google/resolve?name={domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    embed = discord.Embed(
                        title="DNS Lookup Results",
                        color=get_color("dns_lookup")
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🔗 Domain", value=domain, inline=False)
                    
                    if 'Answer' in data:
                        for answer in data['Answer'][:5]:  # Limit to first 5 results
                            record_type = "A" if answer.get('type') == 1 else "AAAA" if answer.get('type') == 28 else f"Type {answer.get('type')}"
                            embed.add_field(name=f"📌 {record_type}", value=answer.get('data', 'N/A'), inline=False)
                    else:
                        embed.description = "No DNS records found"
                    
                    embed.set_footer(text=f"Venice OSINT | Query: {domain}")
                    
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# WHOIS lookup command
@bot.tree.command(name="whois", description="Lookup WHOIS information for a domain or IP")
@app_commands.describe(query="The domain or IP to lookup")
async def whois_lookup(interaction: discord.Interaction, query: str):
    await interaction.response.defer()
    
    try:
        url = f"https://api.hackertarget.com/whois/?q={query}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.text()
                    
                    embed = discord.Embed(
                        title="WHOIS Lookup Results",
                        color=get_color("whois_lookup")
                    )
                    embed.set_author(name="Venice OSINT")
                    
                    if data.strip():
                        formatted_data = data[:1900]  # Discord has a 2000 char limit per field
                        embed.description = f"```\n{formatted_data}\n```"
                    else:
                        embed.description = "No WHOIS information found"
                    
                    embed.set_footer(text=f"Venice OSINT | Query: {query}")
                    
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except asyncio.TimeoutError:
        embed = discord.Embed(
            title="❌ Timeout",
            description="WHOIS lookup timed out. Try again later.",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Nmap scan command
@bot.tree.command(name="nmap", description="Request an Nmap scan")
@app_commands.describe(
    target="The IP address or hostname to scan",
    scan_type="Type of scan (quick, full, ping)"
)
async def nmap_request(interaction: discord.Interaction, target: str, scan_type: str = "quick"):
    await interaction.response.defer()
    
    try:
        if scan_type.lower() == "quick":
            scan_url = f"https://api.hackertarget.com/mrtgscan/?q={target}"
        elif scan_type.lower() == "full":
            scan_url = f"https://api.hackertarget.com/mrtgscan/?q={target}"
        else:  # ping
            scan_url = f"https://api.hackertarget.com/pinglookup/?q={target}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(scan_url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.text()
                    
                    embed = discord.Embed(
                        title="Nmap Scan Results",
                        description=f"Scan Type: **{scan_type.upper()}**",
                        color=get_color("nmap_scan")
                    )
                    embed.set_author(name="Venice OSINT")
                    
                    if data.strip():
                        formatted_data = data[:1900]
                        embed.description = f"Scan Type: **{scan_type.upper()}**\n```\n{formatted_data}\n```"
                    else:
                        embed.description = "No scan results available for this target."
                    
                    embed.set_footer(text=f"Venice OSINT | Target: {target}")
                    
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except asyncio.TimeoutError:
        embed = discord.Embed(
            title="❌ Timeout",
            description="Scan request timed out. Try again later.",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Port scan command
@bot.tree.command(name="portscan", description="Scan common ports on a target")
@app_commands.describe(target="The IP address or hostname to scan")
async def port_scan(interaction: discord.Interaction, target: str):
    await interaction.response.defer()
    
    try:
        url = f"https://api.hackertarget.com/nmap/?q={target}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.text()
                    
                    embed = discord.Embed(
                        title="Port Scan Results",
                        color=get_color("port_scan")
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🎯 Target", value=target, inline=False)
                    
                    if data.strip():
                        formatted_data = data[:1900]
                        embed.description = f"```\n{formatted_data}\n```"
                    else:
                        embed.description = "No open ports found or target unreachable"
                    
                    embed.set_footer(text=f"Venice OSINT | Query: {target}")
                    
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except asyncio.TimeoutError:
        embed = discord.Embed(
            title="❌ Timeout",
            description="Port scan timed out. Try again later.",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# URL scan command (using URLhaus)
@bot.tree.command(name="urlscan", description="Scan a URL for malware/phishing")
@app_commands.describe(url="The URL to scan")
async def url_scan(interaction: discord.Interaction, url: str):
    await interaction.response.defer()
    
    try:
        scan_url = f"https://urlhaus-api.abuse.ch/v1/url/?url={url}"
        async with aiohttp.ClientSession() as session:
            async with session.get(scan_url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    embed = discord.Embed(
                        title="URL Scan Results",
                        color=get_color("url_scan")
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🔗 URL", value=url, inline=False)
                    
                    if data.get('query_status') == 'ok' and data.get('results'):
                        result = data['results'][0]
                        embed.add_field(name="⚠️ Threat Type", value=result.get('threat', 'Unknown'), inline=True)
                        embed.add_field(name="📅 Added", value=result.get('date_added', 'N/A'), inline=True)
                        embed.add_field(name="🔗 Submission", value=result.get('submission_date', 'N/A'), inline=True)
                    else:
                        embed.description = "✅ URL not found in threat database"
                    
                    embed.set_footer(text=f"Venice OSINT | Query: {url}")
                    
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Malware scan command (AlienVault OTX)
@bot.tree.command(name="malwarescan", description="Scan for malware using AlienVault OTX")
@app_commands.describe(
    query="The URL, IP, Domain, or file hash to scan",
    scan_type="Type of scan (url, ip, domain, md5, sha1, sha256)"
)
@app_commands.choices(scan_type=[
    app_commands.Choice(name="URL", value="url"),
    app_commands.Choice(name="IP Address", value="ip"),
    app_commands.Choice(name="Domain", value="domain"),
    app_commands.Choice(name="MD5 Hash", value="md5"),
    app_commands.Choice(name="SHA1 Hash", value="sha1"),
    app_commands.Choice(name="SHA256 Hash", value="sha256")
])
async def malware_scan(interaction: discord.Interaction, query: str, scan_type: str):
    await interaction.response.defer()
    
    api_key = config.get("alienvault_api_key", "")
    if not api_key:
        embed = discord.Embed(
            title="❌ Configuration Error",
            description="AlienVault OTX API key not configured. Please set it in config.json",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        headers = {
            "X-OTX-API-KEY": api_key,
            "User-Agent": "Venice OSINT"
        }
        
        # Map scan types to AlienVault endpoints
        endpoint_mapping = {
            "url": f"https://otx.alienvault.com/api/v1/indicators/url/{query}/general",
            "ip": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general",
            "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{query}/general",
            "md5": f"https://otx.alienvault.com/api/v1/indicators/file/{query}/general",
            "sha1": f"https://otx.alienvault.com/api/v1/indicators/file/{query}/general",
            "sha256": f"https://otx.alienvault.com/api/v1/indicators/file/{query}/general"
        }
        
        url = endpoint_mapping.get(scan_type, "")
        if not url:
            embed = discord.Embed(
                title="❌ Invalid Scan Type",
                description=f"Unknown scan type: {scan_type}",
                color=discord.Color.red()
            )
            embed.set_author(name="Venice OSINT")
            await interaction.followup.send(embed=embed)
            return
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    embed = discord.Embed(
                        title="AlienVault OTX Malware Scan Results",
                        color=get_color("malware_scan")
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🔍 Query", value=query, inline=True)
                    embed.add_field(name="📂 Type", value=scan_type.upper(), inline=True)
                    
                    # Check for threat indicators
                    pulse_info = data.get("pulse_info", {})
                    pulses = pulse_info.get("pulses", [])
                    
                    if pulses:
                        embed.add_field(name="⚠️ Threat Found", value=f"**YES** - {len(pulses)} pulse(s) detected", inline=False)
                        
                        for idx, pulse in enumerate(pulses[:5]):  # Show first 5 pulses
                            pulse_name = pulse.get("name", "Unknown")
                            pulse_modified = pulse.get("modified", "N/A")
                            pulse_tlp = pulse.get("TLP", "N/A")
                            
                            pulse_text = f"**Name:** {pulse_name}\n**TLP:** {pulse_tlp}\n**Modified:** {pulse_modified}"
                            embed.add_field(name=f"Threat #{idx + 1}", value=pulse_text, inline=False)
                        
                        if len(pulses) > 5:
                            embed.add_field(name="⚠️ Note", value=f"Showing 5 of {len(pulses)} threats", inline=False)
                    else:
                        embed.add_field(name="✅ Threat Status", value="No threats detected", inline=False)
                    
                    # Add reputation if available
                    reputation = data.get("reputation", 0)
                    if reputation != 0:
                        embed.add_field(name="📊 Reputation Score", value=str(reputation), inline=True)
                    
                    # Add last analysis date if available
                    last_analysis = data.get("last_analysis_date", "N/A")
                    if last_analysis != "N/A":
                        embed.add_field(name="📅 Last Analyzed", value=last_analysis, inline=True)
                    
                    embed.set_footer(text=f"Venice OSINT | AlienVault OTX")
                    
                    await interaction.followup.send(embed=embed)
                elif response.status == 404:
                    embed = discord.Embed(
                        title="✅ No Threat Data Found",
                        description=f"The {scan_type} '{query}' has no available threat data in AlienVault OTX.",
                        color=discord.Color.green()
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🔍 Query", value=query, inline=True)
                    embed.add_field(name="📂 Type", value=scan_type.upper(), inline=True)
                    embed.set_footer(text=f"Venice OSINT | AlienVault OTX")
                    await interaction.followup.send(embed=embed)
                elif response.status == 401:
                    embed = discord.Embed(
                        title="❌ Authentication Error",
                        description="Invalid AlienVault OTX API key",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except asyncio.TimeoutError:
        embed = discord.Embed(
            title="❌ Timeout",
            description="Malware scan timed out. Try again later.",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# IntelX lookup command
@bot.tree.command(name="intelx", description="Lookup information via IntelX API")
@app_commands.describe(
    search_term="The value to search for",
    search_type="Type of search (uuid, bitcoin, phone, email, creditcard, ssn, ip)"
)
@app_commands.choices(search_type=[
    app_commands.Choice(name="UUID", value="uuid"),
    app_commands.Choice(name="Bitcoin Address", value="bitcoin"),
    app_commands.Choice(name="Phone Number", value="phone"),
    app_commands.Choice(name="Email", value="email"),
    app_commands.Choice(name="Credit Card Number", value="creditcard"),
    app_commands.Choice(name="Social Security Number", value="ssn"),
    app_commands.Choice(name="IP Address", value="ip")
])
async def intelx_lookup(interaction: discord.Interaction, search_term: str, search_type: str):
    await interaction.response.defer()
    
    api_key = config.get("intelx_api_key", "")
    if not api_key:
        embed = discord.Embed(
            title="❌ Configuration Error",
            description="IntelX API key not configured. Please set it in config.json",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
        return
    
    try:
        # IntelX API endpoint
        url = "https://2.intelx.io/phonebook/search"
        
        headers = {
            "User-Agent": "Venice OSINT",
            "x-intelx-apikey": api_key
        }
        
        payload = {
            "term": search_term,
            "buckets": [],
            "lookuptype": 0,
            "maxresults": 100,
            "timeout": 10,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": -1,
            "terminate": [],
            "target": 0
        }
        
        # Map search type to IntelX bucket types
        type_mapping = {
            "uuid": ["uuid"],
            "bitcoin": ["bitcoin"],
            "phone": ["phonenumber"],
            "email": ["email"],
            "creditcard": ["creditcard"],
            "ssn": ["ssn"],
            "ip": ["ipaddress"]
        }
        
        if search_type in type_mapping:
            payload["buckets"] = type_mapping[search_type]
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    embed = discord.Embed(
                        title="IntelX Search Results",
                        color=get_color("intelx_lookup")
                    )
                    embed.set_author(name="Venice OSINT")
                    embed.add_field(name="🔍 Search Term", value=search_term, inline=True)
                    embed.add_field(name="📂 Type", value=search_type.upper(), inline=True)
                    
                    # Check if we have results
                    if data.get("records"):
                        results = data.get("records", [])
                        embed.add_field(name="📊 Results Found", value=str(len(results)), inline=True)
                        
                        # Add up to 10 results
                        for idx, record in enumerate(results[:10]):
                            result_text = record.get("value", "N/A")
                            if len(result_text) > 100:
                                result_text = result_text[:97] + "..."
                            embed.add_field(name=f"Result #{idx + 1}", value=f"```{result_text}```", inline=False)
                        
                        if len(results) > 10:
                            embed.add_field(name="⚠️ Note", value=f"Showing 10 of {len(results)} results", inline=False)
                    else:
                        embed.description = "❌ No results found for this search term"
                    
                    embed.set_footer(text=f"Venice OSINT | Query: {search_term}")
                    
                    await interaction.followup.send(embed=embed)
                elif response.status == 401:
                    embed = discord.Embed(
                        title="❌ Authentication Error",
                        description="Invalid IntelX API key",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
                else:
                    embed = discord.Embed(
                        title="❌ Error",
                        description=f"API returned status code {response.status}",
                        color=discord.Color.red()
                    )
                    embed.set_author(name="Venice OSINT")
                    await interaction.followup.send(embed=embed)
    except asyncio.TimeoutError:
        embed = discord.Embed(
            title="❌ Timeout",
            description="IntelX search timed out. Try again later.",
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error",
            description=str(e),
            color=discord.Color.red()
        )
        embed.set_author(name="Venice OSINT")
        await interaction.followup.send(embed=embed)

# Help command
@bot.tree.command(name="osinthelp", description="Show all available OSINT commands")
async def osint_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Venice OSINT Bot - Command List",
        description=f"All available OSINT reconnaissance commands\n**Prefix:** `{config.get('prefix', 'S')}`",
        color=discord.Color.blurple()
    )
    embed.set_author(name="Venice OSINT")
    
    embed.add_field(name="/iplookup", value="Lookup detailed IP information (geo, ISP, etc.)", inline=False)
    embed.add_field(name="/asnlookup", value="Lookup ASN information for an IP", inline=False)
    embed.add_field(name="/subnetlookup", value="Calculate subnet information", inline=False)
    embed.add_field(name="/reversedns", value="Reverse DNS lookup for an IP", inline=False)
    embed.add_field(name="/dnslookup", value="DNS record lookup for a domain", inline=False)
    embed.add_field(name="/whois", value="WHOIS lookup for domain or IP", inline=False)
    embed.add_field(name="/nmap", value="Nmap scan on target (quick/full/ping)", inline=False)
    embed.add_field(name="/portscan", value="Scan common ports on target", inline=False)
    embed.add_field(name="/urlscan", value="Scan URL for malware/phishing threats", inline=False)
    embed.add_field(name="/malwarescan", value="Scan via AlienVault OTX (URL, IP, Domain, File Hash)", inline=False)
    embed.add_field(name="/intelx", value="Search IntelX database (email, phone, IP, etc.)", inline=False)
    
    embed.set_footer(text="Venice OSINT | Use /commandname for more info")
    
    await interaction.response.send_message(embed=embed)

# Run the bot
if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        print("Error: DISCORD_TOKEN environment variable not set")
        exit(1)
    bot.run(token)
