package be.cytomine.security

import be.cytomine.image.ImageInstance
import be.cytomine.project.Project

import be.cytomine.test.BasicInstance
import be.cytomine.test.Infos

import be.cytomine.test.http.ProjectAPI
import grails.converters.JSON
import be.cytomine.ontology.Annotation
import be.cytomine.test.http.AnnotationAPI

import be.cytomine.test.http.ImageInstanceAPI

/**
 * Created by IntelliJ IDEA.
 * User: lrollus
 * Date: 2/03/11
 * Time: 11:08
 * To change this template use File | Settings | File Templates.
 */
class AnnotationSecurityTests extends SecurityTestsAbstract {

    void testAnnotationSecurityForCytomineAdmin() {
        //Get User 1
        User user = getUser1()

        //Get cytomine admin
        User admin = getUserAdmin()

        //Create project with user 1
        ImageInstance image = ImageInstanceAPI.buildBasicImage(SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Project project = image.project

        //Add annotation 1 with cytomine admin
        Annotation annotation1 = BasicInstance.getBasicAnnotationNotExist()
        annotation1.image = image
        annotation1.project = project
        def result = AnnotationAPI.create(annotation1, SecurityTestsAbstract.USERNAMEADMIN, SecurityTestsAbstract.PASSWORDADMIN)
        assertEquals(200, result.code)
        annotation1 = result.data

        //Add annotation 2 with user 1
        Annotation annotation2 = BasicInstance.getBasicAnnotationNotExist()
        annotation2.image = image
        annotation2.project = project
        Infos.printRight(annotation2.project)
        result = AnnotationAPI.create(annotation2, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        annotation2 = result.data

        //Get/List annotation with cytomine admin
        assertEquals(200, AnnotationAPI.show(annotation2.id, SecurityTestsAbstract.USERNAMEADMIN, SecurityTestsAbstract.PASSWORDADMIN).code)
        result = AnnotationAPI.listByProject(project.id, SecurityTestsAbstract.USERNAMEADMIN, SecurityTestsAbstract.PASSWORDADMIN)
        assertEquals(200, result.code)
        assertTrue(AnnotationAPI.containsInJSONList(annotation2.id, JSON.parse(result.data)))

        //update annotation 2 with cytomine admin
        assertEquals(200, AnnotationAPI.update(annotation2, SecurityTestsAbstract.USERNAMEADMIN, SecurityTestsAbstract.PASSWORDADMIN).code)

        //Delete annotation 2 with cytomine admin
        assertEquals(200, AnnotationAPI.delete(annotation2.id, SecurityTestsAbstract.USERNAMEADMIN, SecurityTestsAbstract.PASSWORDADMIN).code)


    }

    void testAnnotationSecurityForProjectUserAndAnnotationCreator() {
        //Get User 1
        User user = getUser1()

        //Create project with user 1
        ImageInstance image = ImageInstanceAPI.buildBasicImage(SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Project project = image.project

        //Add annotation 1 with user1
        Annotation annotation = BasicInstance.getBasicAnnotationNotExist()
        annotation.image = image
        annotation.project = image.project
        def result = AnnotationAPI.create(annotation, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        annotation = result.data

        //Get/List annotation 1 with user 1
        assertEquals(200, AnnotationAPI.show(annotation.id, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1).code)
        result = AnnotationAPI.listByProject(project.id, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        assertTrue(AnnotationAPI.containsInJSONList(annotation.id, JSON.parse(result.data)))

        //update annotation 1 with user 1
        annotation.refresh()
        assertEquals(200, AnnotationAPI.update(annotation, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1).code)

        //Delete annotation 1 with user 1
        assertEquals(200, AnnotationAPI.delete(annotation.id, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1).code)
    }

    void testAnnotationSecurityForProjectUser() {
        //Get User 1
        User user1 = getUser1()

        //Get User 2
        User user2 = getUser2()

        //Create project with user 1
        ImageInstance image = ImageInstanceAPI.buildBasicImage(SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Project project = image.project

        //Add project right for user 2
        def resAddUser = ProjectAPI.addUserProject(project.id, user2.id, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Infos.printRight(project)
        assertEquals(200, resAddUser.code)

        //Add annotation 1 with user 1
        Annotation annotation = BasicInstance.getBasicAnnotationNotExist()
        annotation.image = image
        annotation.project = image.project
        def result = AnnotationAPI.create(annotation, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        annotation = result.data

        //Get/List annotation 1 with user 2
        assertEquals(200, AnnotationAPI.show(annotation.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)
        result = AnnotationAPI.listByProject(project.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2)
        assertEquals(200, result.code)
        assertTrue(AnnotationAPI.containsInJSONList(annotation.id, JSON.parse(result.data)))

        //update annotation 1 with user 2
        assertEquals(403, AnnotationAPI.update(annotation, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)

        //Delete annotation 1 with user 2
        assertEquals(403, AnnotationAPI.delete(annotation.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)
    }


    void testAnnotationSecurityForUser() {
        //Get User 1
        User user1 = getUser1()

        //Get User 2
        User user2 = getUser2()

        //Create project with user 1
        ImageInstance image = ImageInstanceAPI.buildBasicImage(SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Project project = image.project

        //Add annotation 1 with user 1
        Annotation annotation = BasicInstance.getBasicAnnotationNotExist()
        annotation.image = image
        annotation.project = image.project
        def result = AnnotationAPI.create(annotation, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        annotation = result.data

        //Get/List annotation 1 with user 2
        assertEquals(403, AnnotationAPI.show(annotation.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)
        result = AnnotationAPI.listByProject(project.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2)
        assertEquals(403, result.code)

        //update annotation 1 with user 2
        assertEquals(403, AnnotationAPI.update(annotation, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)

        //Delete annotation 1 with user 2
        assertEquals(403, AnnotationAPI.delete(annotation.id, SecurityTestsAbstract.USERNAME2, SecurityTestsAbstract.PASSWORD2).code)
    }



    void testAnnotationSecurityForAnonymous() {
        //Get User 1
        User user1 = getUser1()

        //Create project with user 1
        ImageInstance image = ImageInstanceAPI.buildBasicImage(SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        Project project = image.project

        //Add annotation 1 with user 1
        Annotation annotation = BasicInstance.getBasicAnnotationNotExist()
        annotation.image = image
        annotation.project = image.project
        def result = AnnotationAPI.create(annotation, SecurityTestsAbstract.USERNAME1, SecurityTestsAbstract.PASSWORD1)
        assertEquals(200, result.code)
        annotation = result.data

        //Get/List annotation 1 with user 2
        assertEquals(401, AnnotationAPI.show(annotation.id, SecurityTestsAbstract.USERNAMEBAD, SecurityTestsAbstract.PASSWORDBAD).code)
        assertEquals(401, AnnotationAPI.listByProject(project.id, SecurityTestsAbstract.USERNAMEBAD, SecurityTestsAbstract.PASSWORDBAD).code)
        assertEquals(401, AnnotationAPI.update(annotation, SecurityTestsAbstract.USERNAMEBAD, SecurityTestsAbstract.PASSWORDBAD).code)
        assertEquals(401, AnnotationAPI.delete(annotation.id, SecurityTestsAbstract.USERNAMEBAD, SecurityTestsAbstract.PASSWORDBAD).code)
    }

}