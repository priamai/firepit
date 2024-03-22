import logging

from firepit.query import Aggregation
from firepit.query import Column
from firepit.query import Count
from firepit.query import CountUnique
from firepit.query import Filter
from firepit.query import Group
from firepit.query import InvalidComparisonOperator
from firepit.query import InvalidQuery
from firepit.query import Join
from firepit.query import Limit
from firepit.query import Offset
from firepit.query import Order
from firepit.query import Predicate
from firepit.query import Projection
from firepit.query import Query
from firepit.query import Table
from firepit.query import Unique

import stix2
from stix2 import Bundle
from stix2.utils import get_type_from_id

import json

class BundleManager(object):
    JSON_KEYS = ['external_references', 'labels','sectors','roles','protocols']

    OBJECT_REFS_CLS = ['observed-data','report','alert','grouping','note', 'opinion']

    DEFAULT_STIX_VERSION ='2.1'
    def __init__(self,store):
        self._store = store

    @classmethod
    def get_ref_query(cls,store, sco_id):

        if "__reflist" in store.types(private=True):
            query = Query()
            query.append(Table("__reflist"))
            query.append(Projection(['ref_name', 'source_ref', 'target_ref']))
            p1 = Predicate("source_ref", "=", sco_id)
            where = Filter([p1])
            query.append(where)

            results = store.run_query(query).fetchall()
            refs = [dict(row) for row in results]

            return refs
        else:
            return []

    @classmethod
    def get_contains_query(cls,store, sco_id):
        query = Query()
        query.append(Table("__contains"))
        query.append(Projection(['source_ref', 'target_ref']))
        p1 = Predicate("source_ref", "=", sco_id)
        where = Filter([p1])
        query.append(where)

        results = store.run_query(query).fetchall()
        refs = [dict(row) for row in results]

        return refs


    @classmethod
    def get_sco_by_id(cls,store, stix_id) -> list[dict]:
        query = Query()
        table_name = get_type_from_id(stix_id)
        query.append(Table(table_name))
        p1 = Predicate("id", "=", stix_id)
        where = Filter([p1])
        query.append(where)

        objects = store.run_query(query).fetchall()

        stix_dicts = []

        for object in objects:
            # augment with all stix fields
            new_object = dict(object)
            new_object['type'] = table_name
            new_object['spec_version'] = cls.DEFAULT_STIX_VERSION
            for key in cls.JSON_KEYS:
                if key in object:
                    if type(object[key]) == str:
                        new_object[key ]=json.loads(object[key ])

            if table_name in cls.OBJECT_REFS_CLS:
                # recompose from __contains
                try:
                    references = cls.get_contains_query(store, new_object['id'])
                    if len(references) > 0:
                        for ref in references:
                            if "object_refs" in new_object:
                                new_object["object_refs"].append(ref["target_ref"])
                            else:
                                new_object["object_refs"] = [ref["target_ref"]]
                except Exception as e:
                    logging.warning(e)
            else:
                # recompose from __reflist
                try:
                    references = cls.get_ref_query(store, new_object['id'])
                    if len(references) > 0:
                        for ref in references:
                            if ref["ref_name"] in new_object:
                                new_object[ref["ref_name"]].append(ref["target_ref"])
                            else:
                                new_object[ref["ref_name"]] = [ref["target_ref"]]
                except Exception as e:
                    logging.warning(e)

            # clean up the None fields
            reduced_object = {k: v for k, v in new_object.items() if v is not None}
            del new_object
            stix_dicts.append(reduced_object)

        return stix_dicts

    @classmethod
    def get_sco_query(cls,store,bundle_id:str)->list[str]:
        query = Query()
        query.append(Table("__queries"))
        query.append(Projection(['sco_id']))
        p1 = Predicate("query_id","=",bundle_id)
        where = Filter([p1])
        query.append(where)
        results = store.run_query(query).fetchall()
        ids = [row['sco_id'] for row in results]
        return ids

    @classmethod
    def write_bundle(cls, store,bundle:Bundle):
        bundle_dict = json.loads(bundle.serialize())
        # nasty hack here it seems to miss the alert objec_refs
        store.cache(bundle.id, bundle_dict)

    @classmethod
    def read_bundle(cls,store,stix_id:str,allow_custom=False)->dict:
        all_sco = cls.get_sco_query(store,stix_id)
        objects = []
        # rebuild the objects
        for sco_id in all_sco:
            object_dicts = cls.get_sco_by_id(store,sco_id)
            objects += object_dicts

        bundle_dict = {"type":"bundle","id":stix_id,"objects":objects}

        bundle = stix2.parse(bundle_dict,allow_custom=allow_custom)

        return bundle

    @classmethod
    def read_bundle_ids(cls, store):
        query = Query()
        query.append(Table("__queries"))
        query.append(Projection(['query_id']))
        p1 = Predicate("query_id", "LIKE","bundle%")
        where = Filter([p1])
        query.append(where)

        results = store.run_query(query).fetchall()
        ids = [row['query_id'] for row in results]

        return ids

    @classmethod
    def delete_bundle(cls,store,stix_id):
        results = store._query(f"SELECT COUNT(*) AS total FROM __queries WHERE query_id='{stix_id}'")
        total_count = 0

        for result in results:
            total_count = result['total']

        for table in store.types():
            if "relationship" in store.tables():
                query_delete_source = f"""
                DELETE FROM "relationship" WHERE source_ref IN (SELECT sco_id FROM "__queries" WHERE query_id = '{stix_id}')
                """
                store._query(query_delete_source)

                query_delete_target = f"""
                DELETE FROM "relationship" WHERE target_ref IN (SELECT sco_id FROM "__queries" WHERE query_id = '{stix_id}')
                """
                store._query(query_delete_target)

            query_delete = f"""
            DELETE FROM "{table}" WHERE id IN (SELECT sco_id FROM "__queries" WHERE query_id = '{stix_id}')
            """

            store._query(query_delete)

        store._query(f"DELETE FROM __queries WHERE query_id='{stix_id}'")
        return total_count
