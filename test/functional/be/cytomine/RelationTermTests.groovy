package be.cytomine

import be.cytomine.test.Infos
import be.cytomine.test.HttpClient
import org.codehaus.groovy.grails.web.json.JSONObject
import grails.converters.JSON
import be.cytomine.ontology.RelationTerm
import be.cytomine.test.BasicInstance
import org.codehaus.groovy.grails.web.json.JSONArray
import be.cytomine.test.http.RelationTermAPI

/**
 * Created by IntelliJ IDEA.
 * User: lrollus
 * Date: 23/02/11
 * Time: 11:01
 * To change this template use File | Settings | File Templates.
 */
class RelationTermTests extends functionaltestplugin.FunctionalTestCase{

    void testShowRelationTerm() {
        RelationTerm relationTerm = BasicInstance.createOrGetBasicRelationTerm()
        def result = RelationTermAPI.show(relationTerm.relation.id,relationTerm.term1.id,relationTerm.term2.id, Infos.GOODLOGIN, Infos.GOODPASSWORD)
        assertEquals(200, result.code)
        def json = JSON.parse(result.data)
        assert json instanceof JSONObject
    }    
    
  void testListRelationTermByTerm1() {
      def result = RelationTermAPI.listByTerm(BasicInstance.createOrGetBasicTerm().id,1, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)
      def json = JSON.parse(result.data)
      assert json instanceof JSONArray
  }

    void testListRelationTermByTerm2() {
        def result = RelationTermAPI.listByTerm(BasicInstance.createOrGetBasicTerm().id,2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
        assertEquals(200, result.code)
        def json = JSON.parse(result.data)
        assert json instanceof JSONArray
    }
    
    void testListRelationTermByRelation() {
        def result = RelationTermAPI.listByRelation(BasicInstance.createOrGetBasicRelation().id, Infos.GOODLOGIN, Infos.GOODPASSWORD)
        assertEquals(200, result.code)
        def json = JSON.parse(result.data)
        assert json instanceof JSONArray
    }    

  void testAddRelationTermCorrect() {
      def relationTermToAdd = BasicInstance.getBasicRelationTermNotExist()

      String jsonRelationTerm = relationTermToAdd.encodeAsJSON()
      def json = JSON.parse(jsonRelationTerm)
      json.relation = relationTermToAdd.relation.id
      json.term1 = relationTermToAdd.term1.id
      json.term2 = relationTermToAdd.term2.id
      int idRelation = relationTermToAdd.relation.id
      int idTerm1 = relationTermToAdd.term1.id
      int idTerm2 = relationTermToAdd.term2.id
      jsonRelationTerm = json.toString()

      def result = RelationTermAPI.create(jsonRelationTerm, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)
      //int idRelationTerm = result.data.id

      result = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)

      result = RelationTermAPI.undo()
      assertEquals(200, result.code)

      result = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(404, result.code)

      result = RelationTermAPI.redo()
      assertEquals(200, result.code)

      result = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)

  }

  void testAddRelationTermAlreadyExist() {
      def relationTermToAdd = BasicInstance.createOrGetBasicRelationTerm()

      String jsonRelationTerm = relationTermToAdd.encodeAsJSON()
      def json = JSON.parse(jsonRelationTerm)
      json.relation = relationTermToAdd.relation.id
      json.term1 = relationTermToAdd.term1.id
      json.term2 = relationTermToAdd.term2.id
      jsonRelationTerm = json.toString()

      def result = RelationTermAPI.create(jsonRelationTerm, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(409, result.code)
  }

  void testAddRelationTermWithRelationNotExist() {
    def relationTermToAdd = BasicInstance.createOrGetBasicRelationTerm()
    String jsonRelationTerm = relationTermToAdd.encodeAsJSON()
    def json = JSON.parse(jsonRelationTerm)
    json.relation = -99
    json.term1 = relationTermToAdd.term1.id
    json.term2 = relationTermToAdd.term2.id
    jsonRelationTerm = json.toString()

      def result = RelationTermAPI.create(jsonRelationTerm, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(400, result.code)
  }

  void testAddRelationTermWithTerm1NotExist() {
      def relationTermToAdd = BasicInstance.createOrGetBasicRelationTerm()
      String jsonRelationTerm = relationTermToAdd.encodeAsJSON()
      def json = JSON.parse(jsonRelationTerm)
      json.relation = relationTermToAdd.relation.id
      json.term1 = -99
      json.term2 = relationTermToAdd.term2.id
      jsonRelationTerm = json.toString()
  
        def result = RelationTermAPI.create(jsonRelationTerm, Infos.GOODLOGIN, Infos.GOODPASSWORD)
        assertEquals(400, result.code)
  }

  void testAddRelationTermWithTerm2NotExist() {
      def relationTermToAdd = BasicInstance.createOrGetBasicRelationTerm()
      String jsonRelationTerm = relationTermToAdd.encodeAsJSON()
      def json = JSON.parse(jsonRelationTerm)
      json.relation = relationTermToAdd.relation.id
      json.term1 = relationTermToAdd.term1.id
      json.term2 = -99
      jsonRelationTerm = json.toString()
  
        def result = RelationTermAPI.create(jsonRelationTerm, Infos.GOODLOGIN, Infos.GOODPASSWORD)
        assertEquals(400, result.code)
  }

  void testDeleteRelationTerm() {
      def relationtermToDelete = BasicInstance.getBasicRelationTermNotExist()
      assert relationtermToDelete.save(flush: true)  != null
      def id = relationtermToDelete.id
      int idRelation = relationtermToDelete.relation.id
      int idTerm1 = relationtermToDelete.term1.id
      int idTerm2 = relationtermToDelete.term2.id
      def result = RelationTermAPI.delete(relationtermToDelete.relation.id,relationtermToDelete.term1.id,relationtermToDelete.term2.id, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)

      def showResult = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(404, showResult.code)

      result = RelationTermAPI.undo()
      assertEquals(200, result.code)

      result = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(200, result.code)

      result = RelationTermAPI.redo()
      assertEquals(200, result.code)

      result = RelationTermAPI.show(idRelation,idTerm1,idTerm2, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(404, result.code)
  }

  void testDeleteRelationTermNotExist() {
      def result = RelationTermAPI.delete(-99,-99,-99, Infos.GOODLOGIN, Infos.GOODPASSWORD)
      assertEquals(404, result.code)
  }


}