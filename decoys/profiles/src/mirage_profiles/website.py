"""The decoy web site: a small company's WordPress site, generated per deployment.

Everything is original: the theme (CSS, a little JavaScript, an SVG logo) is written here, and
the text comes from Faker with the deployment's seed. Nothing is copied from WordPress or
phpMyAdmin; the pages follow their structure, URLs and messages so that scanners and people
see what they expect, not their artwork.

Pages are served as files, as a page-cache plugin serves them (nginx's framing, with
Last-Modified and ETag), so the header order the default-tell checks measure stays nginx's.
What only PHP could answer (logins, XML-RPC, the REST API, the admin redirect) is dynamic.

The site uses its own random streams, so adding a page never changes any other seeded output.
Its WordPress users are the MySQL profile's ``wp_users`` rows, so the REST API, the login
errors and the database agree.
"""

from __future__ import annotations

import html
import json
import random
import re
from datetime import datetime, timedelta
from email.utils import format_datetime
from typing import Any

from faker import Faker

from mirage_profiles import sitecopy

PALETTES = [
    {"brand": "#1f4e79", "accent": "#e07a1f", "ink": "#1d2733", "soft": "#eef3f8"},
    {"brand": "#2d6a4f", "accent": "#d4a017", "ink": "#1b2a22", "soft": "#eef6f1"},
    {"brand": "#5b2a86", "accent": "#e85d75", "ink": "#221a2b", "soft": "#f4eef9"},
    {"brand": "#8c2f1b", "accent": "#2a9d8f", "ink": "#2b1c17", "soft": "#fbf1ec"},
    {"brand": "#0f5e73", "accent": "#f2a541", "ink": "#16262b", "soft": "#ecf6f8"},
    {"brand": "#34495e", "accent": "#27ae60", "ink": "#1c2833", "soft": "#f0f3f5"},
]
NAV = [("Home", "/"), ("About", "/about/"), ("Services", "/services/"), ("Blog", "/blog/"),
       ("Contact", "/contact/")]  # fmt: skip
HTML_TYPE = "text/html; charset=UTF-8"
E = html.escape


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


class Site:
    def __init__(
        self,
        seed: int,
        epoch: datetime,
        title: str,
        wp_users: list[dict[str, str]],
        wordpress_version: str,
        domain: str,
    ) -> None:
        self.rng = random.Random(f"web:{seed}")
        self.fake = Faker("en_US")
        self.fake.seed_instance(seed * 7919 + 17)
        self.epoch = epoch
        self.title = title
        self.users = wp_users
        self.version = wordpress_version
        self.url = f"https://{domain}"
        self.theme = _slug(title.split()[0])
        self.theme_ver = f"1.{self.rng.randint(0, 6)}.{self.rng.randint(0, 9)}"
        self.c = self.rng.choice(PALETTES)
        self.copy = sitecopy.INDUSTRY.get(title.split()[-1], sitecopy.INDUSTRY["Consulting"])
        self.tagline = self.rng.choice(self.copy["hero"])
        self.phone = self.fake.phone_number()
        self.email = f"info@{domain}"
        self.city = self.fake.city()
        self.address = (
            f"{self.fake.street_address()}, {self.city}, {self.fake.state_abbr()} "
            f"{self.fake.zipcode()}"
        )
        self.founded = epoch.year - self.rng.randint(6, 28)
        self.services = self.rng.sample(self.copy["services"], 3)
        self.intro = self.say(self.rng.choice(sitecopy.INTRO))
        self.posts = self._posts()

    # ------------------------------------------------------------------ content

    def say(self, template: str) -> str:
        """Fill a copy template: company, year, city, a service, a person, a client."""
        service = self.rng.choice(self.copy["services"])[0]
        return template.format(
            company=self.title,
            year=self.founded,
            city=self.city,
            service_lower=service.lower(),
            name=self.fake.name(),
            client=self.fake.company(),
            first=self.title.split()[0],
            n=self.rng.randint(3, 7),
        )

    def paragraph(self, bank: list[str], n: int) -> str:
        return " ".join(self.say(t) for t in self.rng.sample(bank, n))

    def _posts(self) -> list[dict[str, Any]]:
        posts = []
        day = self.epoch - timedelta(days=self.rng.randint(3, 20))
        titles = self.rng.sample(sitecopy.POST_TITLES, 5)
        for i in range(5):
            title = self.say(titles[i])
            title = title[0].upper() + title[1:]
            when = day.replace(hour=self.rng.randint(8, 17), minute=self.rng.randint(0, 59))
            slug = _slug(title)
            posts.append(
                {
                    "id": 40 + i * 7 + self.rng.randint(0, 6),
                    "title": title,
                    "slug": slug,
                    "date": when,
                    "url": f"/{when:%Y/%m/%d}/{slug}/",
                    "author": self.users[0]["display_name"] if self.users else "admin",
                    "excerpt": self.paragraph(sitecopy.POST_BODY, 2),
                    "body": [self.paragraph(sitecopy.POST_BODY, 3) for _ in range(3)],
                }
            )
            day -= timedelta(days=self.rng.randint(9, 45))
        return posts

    # ------------------------------------------------------------------ assets

    def css(self) -> str:
        c = self.c
        return f"""/*
Theme Name: {self.title.split()[0]}
Author: {self.title}
Description: Custom theme for {self.title}.
Version: {self.theme_ver}
Requires at least: 6.0
Text Domain: {self.theme}
*/
:root{{--brand:{c["brand"]};--accent:{c["accent"]};--ink:{c["ink"]};--soft:{c["soft"]};--line:#dde3ea}}
*{{box-sizing:border-box}}
body{{margin:0;font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff}}
a{{color:var(--brand)}}
a:hover{{color:var(--accent)}}
.wrap{{max-width:1120px;margin:0 auto;padding:0 24px}}
.site-header{{border-bottom:1px solid var(--line);background:#fff;position:sticky;top:0;z-index:10}}
.site-header .wrap{{display:flex;align-items:center;justify-content:space-between;height:76px}}
.site-branding{{display:flex;align-items:center;gap:12px;text-decoration:none;color:var(--ink)}}
.site-branding img{{width:42px;height:42px}}
.site-title{{font-weight:700;font-size:20px;letter-spacing:.2px}}
.main-navigation ul{{list-style:none;display:flex;gap:28px;margin:0;padding:0}}
.main-navigation a{{text-decoration:none;color:var(--ink);font-weight:500}}
.main-navigation .current-menu-item a{{color:var(--brand);border-bottom:2px solid var(--accent);padding-bottom:4px}}
.menu-toggle{{display:none;background:none;border:1px solid var(--line);border-radius:6px;padding:6px 10px}}
.hero{{background:linear-gradient(135deg,var(--brand),color-mix(in srgb,var(--brand) 55%,#000));color:#fff;padding:96px 0 88px}}
.hero h1{{font-size:44px;line-height:1.15;margin:0 0 16px;max-width:720px}}
.hero p{{font-size:19px;opacity:.9;max-width:620px;margin:0 0 28px}}
.button{{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;padding:13px 26px;border-radius:6px;font-weight:600;border:0;cursor:pointer;font-size:16px}}
.button:hover{{filter:brightness(1.08);color:#fff}}
.section{{padding:72px 0}}
.section.alt{{background:var(--soft)}}
.section h2{{font-size:30px;margin:0 0 28px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px}}
.card{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:28px}}
.card h3{{margin:0 0 10px;font-size:19px}}
.card .icon{{width:44px;height:44px;border-radius:10px;background:var(--soft);color:var(--brand);display:flex;align-items:center;justify-content:center;font-weight:700;margin-bottom:16px}}
.post-list article{{border-bottom:1px solid var(--line);padding:24px 0}}
.post-list h3{{margin:0 0 6px}}
.entry-meta{{color:#6b7785;font-size:14px;margin-bottom:10px}}
.entry-content{{max-width:760px}}
.page-header{{background:var(--soft);padding:56px 0 40px;border-bottom:1px solid var(--line)}}
.page-header h1{{margin:0;font-size:36px}}
.contact-form label{{display:block;font-weight:600;margin:16px 0 6px}}
.contact-form input,.contact-form textarea{{width:100%;max-width:560px;padding:11px 12px;border:1px solid #c5ced8;border-radius:6px;font:inherit}}
.contact-form textarea{{min-height:140px}}
.notice{{background:#edf7ee;border-left:4px solid #2e7d32;padding:14px 18px;margin:0 0 24px;max-width:560px}}
.site-footer{{background:var(--ink);color:#c9d1da;padding:48px 0 28px;font-size:15px}}
.site-footer a{{color:#fff}}
.site-footer .cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:28px}}
.site-footer h4{{color:#fff;margin:0 0 12px}}
.site-info{{border-top:1px solid rgba(255,255,255,.12);margin-top:32px;padding-top:18px;font-size:13px}}
@media (max-width:760px){{.menu-toggle{{display:block}}.main-navigation ul{{display:none;position:absolute;top:76px;left:0;right:0;background:#fff;flex-direction:column;gap:0;border-bottom:1px solid var(--line)}}.main-navigation.toggled ul{{display:flex}}.main-navigation li a{{display:block;padding:14px 24px}}.hero h1{{font-size:32px}}}}
"""

    def js(self) -> str:
        return """( function () {
	var nav = document.getElementById( 'site-navigation' );
	if ( ! nav ) { return; }
	var button = nav.querySelector( '.menu-toggle' );
	if ( ! button ) { return; }
	button.addEventListener( 'click', function () {
		nav.classList.toggle( 'toggled' );
		button.setAttribute( 'aria-expanded', nav.classList.contains( 'toggled' ) ? 'true' : 'false' );
	} );
}() );
"""

    def logo(self) -> str:
        initials = "".join(w[0] for w in self.title.split()[:2]).upper()
        c = self.c
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
            f'<rect width="64" height="64" rx="14" fill="{c["brand"]}"/>'
            f'<path d="M10 48 L26 22 L36 36 L42 28 L54 48 Z" fill="{c["accent"]}" opacity=".9"/>'
            f'<text x="32" y="24" font-family="Arial,Helvetica,sans-serif" font-size="15" '
            f'font-weight="700" fill="#fff" text-anchor="middle">{E(initials)}</text></svg>\n'
        )

    # ------------------------------------------------------------------ page shell

    def theme_url(self, path: str) -> str:
        return f"/wp-content/themes/{self.theme}/{path}"

    def page(self, title: str, body: str, current: str = "", body_class: str = "page") -> str:
        full = E(self.title) if not title else f"{E(title)} &#8211; {E(self.title)}"
        nav = "".join(
            f'<li class="menu-item{" current-menu-item" if href == current else ""}">'
            f'<a href="{href}">{name}</a></li>'
            for name, href in NAV
        )
        year = self.epoch.year
        return f"""<!doctype html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{full}</title>
<meta name='robots' content='max-image-preview:large' />
<link rel="alternate" type="application/rss+xml" title="{E(self.title)} &raquo; Feed" href="{self.url}/feed/" />
<link rel='stylesheet' id='{self.theme}-style-css' href='{self.theme_url("style.css")}?ver={self.theme_ver}' media='all' />
<link rel="https://api.w.org/" href="{self.url}/wp-json/" />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="{self.url}/xmlrpc.php?rsd" />
<meta name="generator" content="WordPress {self.version}" />
<link rel="icon" href="{self.theme_url("assets/logo.svg")}" />
</head>
<body class="{body_class} wp-embed-responsive">
<div id="page" class="site">
<header id="masthead" class="site-header"><div class="wrap">
<a class="site-branding" href="/" rel="home"><img src="{self.theme_url("assets/logo.svg")}" alt="" width="42" height="42"><span class="site-title">{E(self.title)}</span></a>
<nav id="site-navigation" class="main-navigation" aria-label="Primary menu">
<button class="menu-toggle" aria-controls="primary-menu" aria-expanded="false">Menu</button>
<ul id="primary-menu" class="menu">{nav}</ul>
</nav>
</div></header>
<main id="primary" class="site-main">
{body}
</main>
<footer id="colophon" class="site-footer"><div class="wrap">
<div class="cols">
<div><h4>{E(self.title)}</h4><p>{E(self.tagline)}.</p></div>
<div><h4>Contact</h4><p>{E(self.address)}<br>{E(self.phone)}<br><a href="mailto:{self.email}">{self.email}</a></p></div>
<div><h4>Recent posts</h4><p>{"<br>".join(f'<a href="{p["url"]}">{E(p["title"])}</a>' for p in self.posts[:3])}</p></div>
</div>
<div class="site-info">&copy; {year} {E(self.title)}. All rights reserved.</div>
</div></footer>
</div>
<script src='{self.theme_url("assets/js/site.js")}?ver={self.theme_ver}' id='{self.theme}-navigation-js'></script>
</body>
</html>
"""

    def header(self, title: str) -> str:
        return f'<header class="page-header"><div class="wrap"><h1>{E(title)}</h1></div></header>'

    # ------------------------------------------------------------------ pages

    def home(self) -> str:
        cards = "".join(
            f'<div class="card"><div class="icon">{i + 1:02d}</div><h3>{E(t)}</h3><p>{E(d)}</p></div>'
            for i, (t, d) in enumerate(self.services)
        )
        posts = "".join(self.post_teaser(p) for p in self.posts[:3])
        return self.page(
            "",
            f"""<section class="hero"><div class="wrap">
<h1>{E(self.tagline)}</h1>
<p>{E(self.intro)} {E(self.rng.choice(self.copy["about"]))}</p>
<a class="button" href="/contact/">Get in touch</a>
</div></section>
<section class="section"><div class="wrap"><h2>What we do</h2><div class="cards">{cards}</div></div></section>
<section class="section alt"><div class="wrap"><h2>Latest news</h2><div class="post-list">{posts}</div>
<p><a href="/blog/">All posts &rarr;</a></p></div></section>""",
            "/",
            "home page-template-default page",
        )

    def post_teaser(self, p: dict[str, Any]) -> str:
        return (
            f'<article class="post-{p["id"]} post type-post status-publish"><h3>'
            f'<a href="{p["url"]}" rel="bookmark">{E(p["title"])}</a></h3>'
            f'<div class="entry-meta"><time datetime="{p["date"]:%Y-%m-%dT%H:%M:%S}+00:00">'
            f"{p['date']:%B %-d, %Y}</time> &middot; {E(p['author'])}</div>"
            f"<p>{E(p['excerpt'])}</p></article>"
        )

    def about(self) -> str:
        lines = self.copy["about"] + [self.say(t) for t in sitecopy.ABOUT]
        self.rng.shuffle(lines)
        paras = "".join(f"<p>{E(' '.join(lines[i : i + 3]))}</p>" for i in range(0, 6, 3))
        return self.page(
            "About",
            f'{self.header("About us")}<div class="section"><div class="wrap entry-content">'
            f"<p><strong>Founded in {self.founded}</strong>, {E(self.title)} is an "
            f"independent business based in {E(self.city)}.</p>{paras}</div></div>",
            "/about/",
        )

    def services_page(self) -> str:
        cards = "".join(
            f'<div class="card"><h3>{E(t)}</h3><p>{E(d)}</p></div>'
            for t, d in self.copy["services"]
        )
        return self.page(
            "Services",
            f'{self.header("Services")}<div class="section"><div class="wrap">'
            f'<div class="cards">{cards}</div></div></div>',
            "/services/",
        )

    def blog(self) -> str:
        posts = "".join(self.post_teaser(p) for p in self.posts)
        return self.page(
            "Blog",
            f'{self.header("Blog")}<div class="section"><div class="wrap post-list">{posts}'
            "</div></div>",
            "/blog/",
            "blog",
        )

    def post(self, p: dict[str, Any]) -> str:
        body = "".join(f"<p>{E(x)}</p>" for x in p["body"])
        return self.page(
            p["title"],
            f'{self.header(p["title"])}<div class="section"><div class="wrap entry-content">'
            f'<div class="entry-meta">Posted on <time datetime="{p["date"]:%Y-%m-%dT%H:%M:%S}+00:00">'
            f"{p['date']:%B %-d, %Y}</time> by {E(p['author'])}</div>{body}"
            '<p><a href="/blog/">&larr; Back to the blog</a></p></div></div>',
            "/blog/",
            f"post-template-default single single-post postid-{p['id']}",
        )

    def contact(self, sent: bool = False) -> str:
        notice = (
            '<div class="notice" role="status">Thank you for your message. It has been sent.</div>'
            if sent
            else ""
        )
        return self.page(
            "Contact",
            f'{self.header("Contact us")}<div class="section"><div class="wrap">{notice}'
            f"<p>{E(self.address)}<br>Phone: {E(self.phone)}<br>Email: "
            f'<a href="mailto:{self.email}">{self.email}</a></p>'
            '<form class="contact-form" action="/contact/" method="post">'
            '<label for="your-name">Your name</label><input id="your-name" name="your-name" required>'
            '<label for="your-email">Your email</label><input id="your-email" name="your-email" type="email" required>'
            '<label for="your-message">Message</label><textarea id="your-message" name="your-message"></textarea>'
            '<p><button class="button" type="submit">Send</button></p></form></div></div>',
            "/contact/",
        )

    # ------------------------------------------------------------------ WordPress endpoints

    def login_page(self, error: str = "") -> str:
        err = f'<div id="login_error" class="notice notice-error">{error}</div>' if error else ""
        c = self.c
        return f"""<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {E(self.title)} &#8212; WordPress</title>
<meta name='robots' content='noindex, follow' />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>
body.login{{background:#f0f0f1;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#3c434a;margin:0}}
#login{{width:320px;padding:8% 0 0;margin:auto}}
#login h1{{text-align:center;margin:0 0 24px}}
#login h1 a{{display:inline-block;width:84px;height:84px;background:url({self.theme_url("assets/logo.svg")}) center/84px no-repeat;text-indent:-9999px;overflow:hidden}}
#loginform{{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px 34px}}
#loginform label{{font-size:14px;display:block;margin-bottom:3px}}
#loginform input[type=text],#loginform input[type=password]{{width:100%;box-sizing:border-box;font-size:24px;padding:3px 5px;margin:0 6px 16px 0;border:1px solid #8c8f94;border-radius:4px;min-height:40px}}
.forgetmenot{{float:left;margin-top:6px}}
.submit{{text-align:right;margin:0}}
#wp-submit{{background:{c["brand"]};border:1px solid {c["brand"]};color:#fff;border-radius:3px;padding:0 12px;min-height:32px;font-size:13px;cursor:pointer}}
#nav,#backtoblog{{margin:24px 0 0;padding:0 24px}}
#nav a,#backtoblog a{{color:#50575e;text-decoration:none}}
#login_error{{border-left:4px solid #d63638;background:#fff;padding:12px;margin-bottom:20px;box-shadow:0 1px 1px rgba(0,0,0,.04)}}
</style>
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="/">{E(self.title)}</a></h1>
{err}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" /></p>
<div class="user-pass-wrap"><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" /></div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="/wp-admin/" /><input type="hidden" name="testcookie" value="1" /></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
<p id="backtoblog"><a href="/">&larr; Go to {E(self.title)}</a></p>
</div>
</body>
</html>
"""

    def feed(self) -> str:
        items = "".join(
            f"""
	<item>
		<title>{E(p["title"])}</title>
		<link>{self.url}{p["url"]}</link>
		<dc:creator><![CDATA[{p["author"]}]]></dc:creator>
		<pubDate>{format_datetime(p["date"])}</pubDate>
		<category><![CDATA[News]]></category>
		<guid isPermaLink="false">{self.url}/?p={p["id"]}</guid>
		<description><![CDATA[{p["excerpt"]}]]></description>
	</item>"""
            for p in self.posts
        )
        return f"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
	xmlns:content="http://purl.org/rss/1.0/modules/content/"
	xmlns:dc="http://purl.org/dc/elements/1.1/"
	xmlns:atom="http://www.w3.org/2005/Atom"
	xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
	>

<channel>
	<title>{E(self.title)}</title>
	<atom:link href="{self.url}/feed/" rel="self" type="application/rss+xml" />
	<link>{self.url}</link>
	<description>{E(self.tagline)}</description>
	<lastBuildDate>{format_datetime(self.posts[0]["date"])}</lastBuildDate>
	<language>en-US</language>
	<sy:updatePeriod>hourly</sy:updatePeriod>
	<sy:updateFrequency>1</sy:updateFrequency>
	<generator>https://wordpress.org/?v={self.version}</generator>{items}
</channel>
</rss>
"""

    def wp_json(self) -> str:
        return json.dumps(
            {
                "name": self.title,
                "description": self.tagline,
                "url": self.url,
                "home": self.url,
                "gmt_offset": "0",
                "timezone_string": "",
                "namespaces": ["oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-block-editor/v1"],
                "authentication": [],
                "routes": {},
            },
            separators=(",", ":"),
        )

    def wp_users_json(self) -> str:
        return json.dumps(
            [
                {
                    "id": int(u["id"]),
                    "name": u["display_name"],
                    "url": "",
                    "description": "",
                    "link": f"{self.url}/author/{u['login']}/",
                    "slug": u["login"],
                }
                for u in self.users
            ],
            separators=(",", ":"),
        )

    def xmlrpc_fault(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse>\n  <fault>\n    <value>\n'
            "      <struct>\n        <member>\n          <name>faultCode</name>\n"
            "          <value><int>403</int></value>\n        </member>\n        <member>\n"
            "          <name>faultString</name>\n"
            "          <value><string>Incorrect username or password.</string></value>\n"
            "        </member>\n      </struct>\n    </value>\n  </fault>\n</methodResponse>\n"
        )

    # ------------------------------------------------------------------ phpMyAdmin

    def pma_page(self, error: str = "") -> str:
        err = (
            f'<div class="alert alert-danger" role="alert"><img src="themes/dot.gif" '
            f'title="" alt="" class="icon ic_s_error"> {error}</div>'
            if error
            else ""
        )
        return f"""<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow,notranslate">
<meta name="google" content="notranslate">
<title>phpMyAdmin</title>
<style>
body{{background:#eee;font:14px/1.5 Helvetica,Arial,sans-serif;color:#444;margin:0}}
.container{{max-width:420px;margin:60px auto}}
h1{{text-align:center;font-weight:400;font-size:26px;margin:0 0 6px}}
h1 .pma{{color:#235a81;font-weight:700}}
.sub{{text-align:center;color:#888;margin-bottom:24px}}
.card{{background:#fff;border:1px solid #aaa;border-radius:4px}}
.card-header{{background:#f3f3f3;border-bottom:1px solid #aaa;padding:8px 14px;font-weight:700}}
.card-body{{padding:16px 14px}}
.row{{display:flex;align-items:center;margin:0 0 12px}}
.row label{{width:110px}}
.row input,.row select{{flex:1;padding:5px 6px;border:1px solid #aaa;border-radius:2px;font:inherit}}
.card-footer{{background:#f3f3f3;border-top:1px solid #aaa;padding:8px 14px;text-align:right}}
.btn{{background:#ddd;border:1px solid #aaa;padding:5px 14px;border-radius:2px;cursor:pointer;font:inherit}}
.alert-danger{{background:#f8d7da;border:1px solid #f5c2c7;color:#842029;padding:10px 12px;border-radius:3px;margin:0 0 16px}}
</style>
</head>
<body id="loginform">
<div class="container">
<h1>Welcome to <span class="pma">phpMyAdmin</span></h1>
<div class="sub">Language: English</div>
{err}
<form method="post" id="login_form" action="index.php?route=/" name="login_form" class="disableAjax hide js-show" autocomplete="off">
<div class="card">
<div class="card-header">Log in</div>
<div class="card-body">
<div class="row"><label for="input_username">Username:</label><input type="text" name="pma_username" id="input_username" value="" autocomplete="username" spellcheck="false"></div>
<div class="row"><label for="input_password">Password:</label><input type="password" name="pma_password" id="input_password" value="" autocomplete="current-password" spellcheck="false"></div>
<input type="hidden" name="server" value="1">
<input type="hidden" name="route" value="/">
</div>
<div class="card-footer"><input class="btn" value="Log in" type="submit" id="input_go"></div>
</div>
</form>
</div>
</body>
</html>
"""

    # ------------------------------------------------------------------ routes

    def routes(self) -> list[dict[str, Any]]:
        def file(path: str, body: str, ctype: str = HTML_TYPE) -> dict[str, Any]:
            return {"path": path, "methods": ["GET", "HEAD"], "status": 200,
                    "content_type": ctype, "body": body}  # fmt: skip

        logins = [u["login"] for u in self.users] + [u["email"] for u in self.users]
        login_error = "<strong>Error:</strong> "
        routes = [
            file("/", self.home()),
            file("/about/", self.about()),
            file("/services/", self.services_page()),
            file("/blog/", self.blog()),
            *(file(p["url"], self.post(p)) for p in self.posts),
            {
                **file("/contact/", self.contact()),
                "methods": ["GET", "HEAD", "POST"],
                "post_body": self.contact(sent=True),
            },
            file(self.theme_url("style.css"), self.css(), "text/css"),
            file(self.theme_url("assets/js/site.js"), self.js(), "application/javascript"),
            file(self.theme_url("assets/logo.svg"), self.logo(), "image/svg+xml"),
            {**file("/feed/", self.feed(), "application/rss+xml; charset=UTF-8"), "dynamic": True},
            {
                **file("/wp-json/", self.wp_json(), "application/json; charset=UTF-8"),
                "dynamic": True,
            },
            {
                **file(
                    "/wp-json/wp/v2/users", self.wp_users_json(), "application/json; charset=UTF-8"
                ),
                "dynamic": True,
            },
            {
                "path": "/xmlrpc.php",
                "methods": ["GET", "HEAD", "POST"],
                "status": 200,
                "dynamic": True,
                "content_type": "text/plain;charset=UTF-8",
                "body": "XML-RPC server accepts POST requests only.",
                "post_body": self.xmlrpc_fault(),
            },
            {
                "path": "/wp-admin/",
                "methods": ["GET", "HEAD"],
                "status": 302,
                "dynamic": True,
                "content_type": HTML_TYPE,
                "redirect": "/wp-login.php?redirect_to={self}&reauth=1",
                "body": "",
            },
            {
                "path": "/wp-admin/admin-ajax.php",
                "methods": ["GET", "HEAD", "POST"],
                "status": 400,
                "dynamic": True,
                "content_type": HTML_TYPE,
                "body": "0",
            },
            {
                "path": "/wp-login.php",
                "methods": ["GET", "HEAD", "POST"],
                "status": 200,
                "content_type": HTML_TYPE,
                "capture": "credentials",
                "fields": ["log", "pwd"],
                "body": self.login_page(),
                "known_users": logins,
                "post_bodies": {
                    "empty": self.login_page(
                        login_error
                        + "The username field is empty.<br />"
                        + login_error
                        + "The password field is empty."
                    ),
                    "known": self.login_page(
                        login_error + "The password you entered for the username "
                        "<strong>{username}</strong> is incorrect. "
                        '<a href="/wp-login.php?action=lostpassword">'
                        "Lost your password?</a>"
                    ),
                    "unknown": self.login_page(
                        login_error + "The username <strong>{username}</strong> is not "
                        "registered on this site. If you are unsure of your username, try your "
                        "email address instead."
                    ),
                },
            },
        ]
        pma_denied = self.pma_page(
            "mysqli::real_connect(): (HY000/1045): Access denied for user "
            "'{username}'@'localhost' (using password: YES)"
        )
        for path in ("/phpmyadmin/", "/phpmyadmin/index.php"):
            routes.append(
                {
                    "path": path,
                    "methods": ["GET", "HEAD", "POST"],
                    "status": 200,
                    "content_type": "text/html; charset=utf-8",
                    "capture": "credentials",
                    "fields": ["pma_username", "pma_password"],
                    "body": self.pma_page(),
                    "post_body": pma_denied,
                }
            )
        return routes
