#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import json
import django
try:
    sys.path.append("/opt/vulture")
    sys.path.append("/opt/vulture/admin")
    sys.path.append("/opt/vulture/lib/Python/modules")
    VPATH = "/opt/vulture/admin/"
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
    from vulture.migrations import *
except:
    sys.path.append("/var/www/vulture")
    sys.path.append("/var/www/vulture/admin")
    sys.path.append("/opt/vulture/lib/Python/modules")
    VPATH = "/var/www/vulture/admin/"
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
from django.db.models import get_app, get_models
from django.conf import settings
from django.core.management import call_command
import sqlite3

class Migrate():
    def __init__(self, dest_version=None):
        self.model_list = list()
        app = get_app('vulture')
        for model in get_models(app):
            model_name = "vulture." + model.__name__
            self.model_list.append(model_name)
        if dest_version:
            import_name = dest_version
        else :    
            import_name    = 'changes_2_0_8'
        try:
            self.model_changes = __import__('migrations.' + import_name, fromlist=[import_name])
        except ImportError:
            print "Wrong update parameter"
            os.system("cp "+VPATH+"vulture/models_final.py "+VPATH+"vulture/models.py")
            sys.exit(0)

        self.changes_queue = list()
        
    def prepare_migration(self):
        """ preparing migration (backup old data and check model's changes) """
        os.system("rm "+VPATH+"vulture/fixtures/vulture.*.json")
        for model in self.model_list:
            self.export_data(model)
            if self.model_has_changed(model):
                self.changes_queue.append(model)
                print model + " has changed"

    def model_has_changed(self, model):
        """ Return true if model has changed """
        new_fields = {}
        removed_fields = {}
        moved_fields = {}
        try:
            new_fields = self.model_changes.new_fields
            removed_fields = self.model_changes.removed_fields
            moved_fields = self.model_changes.moved_fields
        except AttributeError:
            pass

        if model in new_fields:
            return True
        elif model in removed_fields:
            return True
        elif model in moved_fields:
            return True
        else:
            return False

    def export_data(self, model, dumpdata = True):
        """ Exporting initial data into a json file """
        model_export_name = model
        if dumpdata == True:
            try:
                sysout = sys.stdout
                sys.stdout =  open(VPATH+'vulture/fixtures/'+ model_export_name +'.json','w')
                call_command('dumpdata', model_export_name)
                sys.stdout = sysout
            except django.db.utils.DatabaseError as e:
                os.system("cp "+VPATH+"vulture/models_final.py "+VPATH+"vulture/models.py")#Error : restoring target model
                sys.stdout = sysout
                print e
                print "error on model : " + model_export_name
                sys.exit(0)
        else:
            f = open(VPATH+'vulture/fixtures/'+ model_export_name +'.json','w')
            json_data = json.dumps(dumpdata)
            f.write(json_data)

    def load_json(self, fname):
        """ Open and decode json file from his model name """
        try:
            f = open(VPATH+'vulture/fixtures/' + fname + '.json','r')
            tmp = f.read()
            content = json.loads(tmp)
        except IOError:
            content = []
        return content

    def load_data(self):
        """ load fixture data into database (final)"""
        for model in self.changes_queue:
            cmd = os.popen("python "+VPATH+"manage.py loaddata "+ model +".json")
            print cmd.read()

    def apply_changes(self):
        self.add_fields()
        self.move_fields()
        self.remove_fields()

    def add_fields(self, one_model = None):
        """ Adding new fields """
        if one_model is None:
            model_list = self.changes_queue
        else:
            model_list = [one_model]
        for model in model_list:
            try:
                new_fields = self.model_changes.new_fields[model]
            except (AttributeError, KeyError) as e:
                continue
            content = self.load_json(model)
            for entry in content:
                for field in new_fields:
                    name  = field['name']
                    value = field['value']
                    if name in entry['fields']: #field already exist
                        continue
                    if 'ask' in field and field['ask']: #ask value
                        value = self.ask_user(field, model, entry['fields'])
                    entry['fields'][name] = value
            self.export_data(model, content)

    def remove_fields(self):
        """ Remove fields from model """
        for model in self.changes_queue:
            try:
                removed_fields = self.model_changes.removed_fields[model]
            except (AttributeError, KeyError) as e:
                continue
            content = self.load_json(model)
            for entry in content:
                for field in removed_fields:
                    name  = field['name']
                    try:
                        del entry['fields'][name]
                    except KeyError:
                        continue
            self.export_data(model, content)

    def move_fields(self):
        """ move fields from a model into another model """
        for model in self.changes_queue:
            try:
                moved_fields = self.model_changes.moved_fields[model]
            except (AttributeError, KeyError) as e:
                continue
            content = self.load_json(model)
            for entry in content:
                fields = {}
                first_time = False
                for field in moved_fields:
                    # retrieving value to move
                    replace_field = field['replacement_field']
                    src_field  = field['src_field']
                    src_value = entry['fields'][src_field]
                    dest_model = field['dest_model']
                    dest_field = field['dest_field']
                    dest_content = self.load_json(dest_model)
                    #saving values
                    if first_time != True:
                        first_time = True
                        try:
                            pk = dest_content[-1]['pk'] + 1 
                        except IndexError:
                            pk = 1
                    fields[dest_field] = src_value
                self.changes_queue.append(dest_model)
                dest_content.append({'pk':pk, 'model':dest_model.lower(), 'fields': fields})
                entry['fields'][replace_field] = pk # foreign key in src model to new fields in dest model
                self.export_data(dest_model, dest_content)
                self.add_fields(dest_model)#adding other fields if needed
                self.export_data(model, content)

    def ask_user(self, attribute, model, entry, first=True):
        if first:
            print model + " : this entry need to be updated : "
            print entry
            print "You have to specify a value for new field '" + attribute['name'] + "' :"
            print "This field is used for : " + attribute['legend']
            print "Default value is : " + attribute['value'] + ", you can let a blank field for default value "
        value = raw_input("value : ")

        if value == '': # Return default value
            return attribute['value']
        if attribute['type'] == "int":
            try :
                value = int(value)
                return value
            except Exception:
                print "Value must be int, please retry :"
                value = self.ask_user(attribute, model, entry, False)
        else :
            return value

    def update_database(self):
        """ Deleting modified tables and populate data"""
        os.system("cp "+VPATH+"vulture/models_final.py "+VPATH+"vulture/models.py")
        os.system("rm "+VPATH+"vulture/models.pyc")
        con = sqlite3.connect(VPATH+"db")
        for model in self.changes_queue:
            try:
                cur = con.cursor()
                tmp = model.split('.')
                table_name = tmp[1].lower()
                if table_name == 'appearance':#handle model divergency
                    table_name = 'style_style'
                cur.executescript(unicode("drop table "+table_name+";"))
                cur.close() 
            except sqlite3.OperationalError: 
                pass
        con.close()
        os.system("python "+VPATH+"manage.py syncdb --noinput")
        self.load_data()

    def process_migration(self):
        self.prepare_migration()
        self.apply_changes()
        self.update_database()
        try:
            con = sqlite3.connect(VPATH+"db")
            cur = con.cursor()
            cur.execute("UPDATE conf set value='2.0.8' where id=1")
            con.commit()
            con.close()
        except:
            pass

""" Migration 2.0.7 ==> 2.0.8 """
if len(sys.argv) == 1: 
    #Setting up old model and backup old db
    os.system("mv "+VPATH+"vulture/models.py "+VPATH+"vulture/models_final.py")
    os.system("cp "+VPATH+"vulture/models.py.old "+VPATH+"vulture/models.py")
    os.system("cp "+VPATH+"db "+VPATH+"db_old_migration")

    #Used to fix bug about datatype in sso table
    try:
        con = sqlite3.connect(VPATH+"db")
        cur = con.cursor()
        cur.execute("DELETE FROM sso where id=1")
        cur.execute("INSERT INTO sso VALUES(1,'Htaccess','sso_forward_htaccess',NULL,NULL,NULL,NULL,NULL,0,'1',NULL,NULL,'',NULL,'',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0)")
        con.commit()
        con.close()
    except:
        pass

    #Migration
    a = Migrate()
    a.process_migration()
    os.system("cp "+VPATH+"vulture/models_final.py "+VPATH+"vulture/models.py")#restore model in case of error
    """Apply a patch"""
else :
    dest_version = sys.argv[1]
    os.system("cp "+VPATH+"db "+VPATH+"db_old_migration_"+dest_version)
    os.system("mv "+VPATH+"vulture/models.py "+VPATH+"vulture/models_final.py")
    os.system("cp "+VPATH+"vulture/models.py.old "+VPATH+"vulture/models.py")
    a = Migrate(dest_version)
    a.process_migration()
