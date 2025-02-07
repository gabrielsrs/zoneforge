from flask import Flask, render_template, request, redirect, url_for, flash
from flask_restx import Api
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_minify import minify
from zoneforge.api.status import api as ns_status
from zoneforge.api.types import api as ns_types
from zoneforge.api.types import RecordTypeResource
from zoneforge.api.zones import api as ns_zone
from zoneforge.api.zones import DnsZone, get_zones
from zoneforge.api.records import api as ns_record
from zoneforge.api.records import DnsRecord
from zoneforge.modal_data import *
import zoneforge.authentication as auth
from db import db
import os
import logging
import sys

def create_app():
    # Flask App setup
    app = Flask(__name__, static_folder='static', static_url_path='')

    # Configuration with environment variables and defaults
    log_config = {}
    log_config['level'] = os.environ.get('LOG_LEVEL', 'WARNING').upper()
    log_config['format'] = "%(levelname)s [%(filename)-s%(funcName)s():%(lineno)s]: %(message)s"
    if not os.environ.get('CONTAINER', False):
        log_config['format'] = f"[%(asctime)s] {log_config['format']}"
    log_config['handlers'] = [logging.StreamHandler(sys.stdout)]
    logging.basicConfig(**log_config)

    app.config['ZONE_FILE_FOLDER'] = os.environ.get('ZONE_FILE_FOLDER', './lib/examples')
    app.config['DEFAULT_ZONE_TTL'] = int(os.environ.get('DEFAULT_ZONE_TTL', '86400'))
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret_key')
    app.config['TOKEN_SECRET'] = os.environ.get('TOKEN_SECRET', 'token_secret')
    app.config['REFRESH_TOKEN_SECRET'] = os.environ.get('REFRESH_TOKEN_SECRET', 'refresh_token_secret')

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///zoneinfo.db')
    db.init_app(app)

    with app.app_context():
        db.create_all()

    minify(app=app, html=True, js=True, cssless=True, static=True)
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )
    # API Setup
    api = Api(app, prefix= '/api', doc='/api', validate=True)

    @app.route("/", methods=['GET'])
    def home():
        zf_zone = DnsZone()
        try:
            zones = zf_zone.get()
        except:
            zones = []
        zone_create_defaults = ZONE_DEFAULTS | ZONE_PRIMARY_NS_DEFAULTS
        return render_template('home.html.j2', zones=zones, modal=ZONE_CREATION, modal_api='/api/zones', modal_default_values=zone_create_defaults)

    @app.route("/zone/<string:zone_name>", methods=['GET'])
    def zone(zone_name):
        zone = get_zones(zone_name=zone_name)[0].to_response()
        zf_record = DnsRecord()
        records = zf_record.get(zone_name=zone_name)
        current_zone_data = {
            "name": zone_name,
            "soa_ttl": zone['soa']['ttl'],
            "admin_email": zone['soa']['data']['rname'],
            "refresh": zone['soa']['data']['refresh'],
            "retry": zone['soa']['data']['retry'],
            "expire": zone['soa']['data']['expire'],
            "minimum": zone['soa']['data']['minimum'],
            "primary_ns": zone['soa']['data']['mname'],
        }
        record_types = RecordTypeResource()
        record_types_list = record_types.get()
        user_sort = request.args.get("sort", "name")
        user_sort_order = request.args.get("sort_order", "desc")
        return render_template('zone.html.j2', zone=zone, modal=ZONE_EDIT, modal_default_values=current_zone_data, records=records, record_types=record_types_list, record_sort=user_sort, record_sort_order=user_sort_order)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            login_response = auth.LoginResource().post()

            if login_response[1] != 200:
                flash(login_response[0])

                return render_template('login.html.j2')

            return redirect(url_for('home'))
        return render_template('login.html.j2')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            signup_response = auth.SignupResource().post()

            flash(signup_response[0])

            if signup_response[1] != 200:

                return render_template('signup.html.j2')

            return redirect(url_for('login'))
        return render_template('signup.html.j2')


    api.add_namespace(ns_status)
    api.add_namespace(ns_zone)
    api.add_namespace(ns_record)
    api.add_namespace(ns_types)

    api.add_resource(auth.LoginResource, '/login')
    api.add_resource(auth.RefreshTokenResource, '/refresh')
    api.add_resource(auth.SignupResource, '/signup')

    return app

if __name__=="__main__":
    dev = create_app()
    dev.run()
else:
    production = create_app()
