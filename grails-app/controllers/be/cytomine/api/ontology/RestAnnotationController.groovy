package be.cytomine.api.ontology

import be.cytomine.api.RestController
import be.cytomine.api.UrlApi
import be.cytomine.image.ImageInstance
import be.cytomine.ontology.Annotation
import be.cytomine.ontology.Term
import be.cytomine.project.Project
import be.cytomine.security.User
import grails.converters.JSON

import java.text.SimpleDateFormat
import be.cytomine.ontology.AnnotationTerm
import be.cytomine.Exception.WrongArgumentException
import be.cytomine.Exception.CytomineException

import be.cytomine.security.SecUser
import be.cytomine.social.SharedAnnotation
import java.awt.image.BufferedImage
import javax.imageio.ImageIO

import be.cytomine.processing.Job
import org.codehaus.groovy.grails.web.json.JSONArray

class RestAnnotationController extends RestController {

    def exportService
    def grailsApplication
    def annotationService
    def termService
    def imageInstanceService
    def userService
    def projectService
    def cytomineService
    def mailService

    def list = {
        def annotations = []
        def projects = projectService.list()
        projects.each {
            annotations.addAll(annotationService.list(it))
        }
        responseSuccess(annotations)
    }

    def listByImage = {
        ImageInstance image = imageInstanceService.read(params.long('id'))
        if (image) responseSuccess(annotationService.list(image))
        else responseNotFound("Image", params.id)
    }

    def listByProject = {
        Project project = projectService.read(params.long('id'), new Project())

        Collection<SecUser> userList = []
        if (params.users != null && params.users != "null") {
            if (params.users != "") userList = userService.list(project, params.users.split("_").collect{ Long.parseLong(it)})
        }
        else {
            userList = userService.list(project)
        }
        Collection<ImageInstance> imageInstanceList = []
        if (params.images != null && params.images != "null") {
            if (params.images != "") imageInstanceList = imageInstanceService.list(project, params.images.split("_").collect{ Long.parseLong(it)})
        } else {
            imageInstanceList = imageInstanceService.list(project)
        }

        if (project) responseSuccess(annotationService.list(project, userList, imageInstanceList, (params.noTerm == "true"), (params.multipleTerm == "true")))
        else responseNotFound("Project", params.id)
    }

    def listByImageAndUser = {
        def image = imageInstanceService.read(params.long('idImage'))
        def user = userService.read(params.idUser)
        if (image && user && params.bbox) {
            responseSuccess(annotationService.list(image, user, (String) params.bbox))
        }
        else if (image && user) responseSuccess(annotationService.list(image, user))
        else if (!user) responseNotFound("User", params.idUser)
        else if (!image) responseNotFound("Image", params.idImage)
    }

    def listAnnotationByTerm = {
        Term term = termService.read(params.long('idterm'))
        if (term) responseSuccess(annotationService.list(term))
        else responseNotFound("Annotation Term", "Term", params.idterm)
    }

    def listAnnotationByProjectAndTerm = {
        Term term = termService.read(params.long('idterm'))
        Project project = projectService.read(params.long('idproject'), new Project())

        Collection<SecUser> userList = []
        if (params.users != null && params.users != "null") {
            if (params.users != "") userList = userService.list(project, params.users.split("_").collect{ Long.parseLong(it)})
        }
        else {
            userList = userService.list(project)
        }
        Collection<ImageInstance> imageInstanceList = []
        if (params.images != null && params.images != "null") {
            if (params.images != "") imageInstanceList = imageInstanceService.list(project, params.images.split("_").collect{ Long.parseLong(it)})
        } else {
            imageInstanceList = imageInstanceService.list(project)
        }

        if (term == null) responseNotFound("Term", params.idterm)
        else if (project == null) responseNotFound("Project", params.idproject)
        /*else if (userList.isEmpty()) responseNotFound("Users", params.users)
        else if (imageInstanceList.isEmpty()) responseNotFound("ImageInstance", params.images)*/
        else if(!params.suggestTerm) {
            responseSuccess(annotationService.list(project, term, userList, imageInstanceList))
        }
        else {
            Term suggestedTerm = termService.read(params.suggestTerm)
            responseSuccess(annotationService.list(project, userList, term, suggestedTerm, Job.read(params.long('job'))))
        }
    }

    def downloadDocumentByProject = {  //and filter by users and terms !
        // Export service provided by Export plugin

        Project project = projectService.read(params.long('id'),new Project())
        if (!project) responseNotFound("Project", params.long('id'))

        projectService.checkAuthorization(project)
        def users = []
        if (params.users != null) {
            params.users.split(",").each { id ->
                users << Long.parseLong(id)
            }
        }
        def terms = []
        if (params.terms != null) {
            params.terms.split(",").each {  id ->
                terms << Long.parseLong(id)
            }
        }
        def images = []
        if (params.images != null) {
            params.images.split(",").each {  id ->
                images << Long.parseLong(id)
            }
        }
        def termsName = Term.findAllByIdInList(terms).collect{ it.toString() }
        def usersName = SecUser.findAllByIdInList(users).collect{ it.toString() }
        def imageInstances = ImageInstance.findAllByIdInList(images)

        if (params?.format && params.format != "html") {
            def exporterIdentifier = params.format;
            if (exporterIdentifier == "xls") exporterIdentifier = "excel"
            response.contentType = grailsApplication.config.grails.mime.types[params.format]
            SimpleDateFormat  simpleFormat = new SimpleDateFormat("yyyyMMdd_hhmmss");
            String datePrefix = simpleFormat.format(new Date())
            response.setHeader("Content-disposition", "attachment; filename=${datePrefix}_annotations_project${project.id}.${params.format}")

            def annotations = Annotation.createCriteria().list {
                eq("project", project)
                inList("image", imageInstances)
                inList("user.id", users)
            }

            def annotationTerms = AnnotationTerm.createCriteria().list {
                inList("annotation", annotations)
                inList("term.id", terms)
                order("term.id", "asc")
            }

            def exportResult = []
            annotationTerms.each { annotationTerm ->
                Annotation annotation = annotationTerm.annotation
                def centroid = annotation.getCentroid()
                Term term = annotationTerm.term
                def data = [:]
                data.id = annotation.id
                data.area = annotation.computeArea()
                data.perimeter = annotation.computePerimeter()
                if (centroid != null) {
                    data.XCentroid = (int) Math.floor(centroid.x)
                    data.YCentroid = (int) Math.floor(centroid.y)
                } else {
                    data.XCentroid = "undefined"
                    data.YCentroid = "undefined"
                }
                data.image = annotation.image.id
                data.filename = annotation.getFilename()
                data.user = annotation.user.toString()
                data.term = term.name
                data.cropURL =UrlApi.getAnnotationCropWithAnnotationId(grailsApplication.config.grails.serverURL,annotation.id)
                data.cropGOTO = UrlApi.getAnnotationURL(grailsApplication.config.grails.serverURL,annotation.image.getIdProject(), annotation.image.id, annotation.id)
                exportResult.add(data)
            }

            List fields = ["id", "area", "perimeter", "XCentroid", "YCentroid", "image", "filename", "user", "term", "cropURL", "cropGOTO"]
            Map labels = ["id": "Id", "area": "Area (µm²)", "perimeter": "Perimeter (µm)", "XCentroid" : "X", "YCentroid" : "Y", "image": "Image Id", "filename": "Image Filename", "user": "User", "term": "Term", "cropURL": "View annotation picture", "cropGOTO": "View annotation on image"]
            String title = "Annotations in " + project.getName() + " created by " + usersName.join(" or ") + " and associated with " + termsName.join(" or ") + " @ " + (new Date()).toLocaleString()

            exportService.export(exporterIdentifier, response.outputStream, exportResult, fields, labels, null, ["column.widths": [0.04,0.06,0.06,0.04, 0.04, 0.04,0.08,0.06,0.06,0.25,0.25], "title": title, "csv.encoding": "UTF-8", "separator": ";"])
        }
    }


    def addComment = {
        //try {
        User sender = User.read(springSecurityService.principal.id)
        Annotation annotation = Annotation.read(request.JSON.annotation)
        log.info "add comment from " + sender + " and annotation " + annotation
        File annnotationCrop = null
        try {
            BufferedImage bufferedImage = getImageFromURL(annotation.toCropURL())
            annnotationCrop = File.createTempFile("temp", ".jpg")
            annnotationCrop.deleteOnExit()
            ImageIO.write(bufferedImage, "JPG", annnotationCrop)
        } catch (FileNotFoundException e) {
            annnotationCrop = null
        }
        List<User> receivers = request.JSON.users.collect { userID ->
            User.read(userID)
        }
        String[] receiversEmail = new String[receivers.size()]
        for (int i = 0; i < receivers.size(); i++) {
            receiversEmail[i] = receivers[i].getEmail();
        }
        log.info "send mail to " + receiversEmail
        def sharedAnnotation = new SharedAnnotation(
                sender : sender,
                receiver : receivers,
                comment : request.JSON.comment,
                annotation: annotation
        )
        def attachments = []
        if (annnotationCrop != null) attachments << [cid : "annotation", file : annnotationCrop]
        if (sharedAnnotation.save()) {
            mailService.send("cytomine.ulg@gmail.com", receiversEmail, sender.getEmail(), request.JSON.subject, request.JSON.message, attachments)
            response([success: true, message: "Annotation shared to " + receivers.toString()], 200)
        } else {
            response([success: false, message: "Error"], 400)
        }
        /* } catch (Exception e) {
            response([success: false, message: e.toString()], 400)
        }*/

    }

    def showComment = {
        Annotation annotation = annotationService.read(params.long('annotation'))
        User user = User.read(springSecurityService.principal.id)
        if (!annotation)  responseNotFound("Annotation", params.annotation)
        annotationService.checkAuthorization(annotation.project)
        def sharedAnnotation = SharedAnnotation.findById(params.long('id'))
        if (!sharedAnnotation) responseNotFound("SharedAnnotation", params.id)
        responseSuccess(sharedAnnotation)
    }

    def listComments = {
        Annotation annotation = annotationService.read(params.long('annotation'))
        User user = User.read(springSecurityService.principal.id)
        if (annotation) {
            annotationService.checkAuthorization(annotation.project)
            def sharedAnnotations = SharedAnnotation.createCriteria().list {
                eq("annotation", annotation)
                or {
                    eq("sender", user)
                    receiver {
                        eq("id", user.id)
                    }
                }
                order("created", "desc")
            }
            responseSuccess(sharedAnnotations.unique())
        } else {
            responseNotFound("Annotation", params.id)
        }
    }

    def show = {

        Annotation annotation = annotationService.read(params.long('id'))

        if (annotation) {
            annotationService.checkAuthorization(annotation.project)
            responseSuccess(annotation)
        }
        else responseNotFound("Annotation", params.id)
    }

    def add = {
        def json = request.JSON
        if (json instanceof org.codehaus.groovy.grails.web.json.JSONArray) {
            def result = [:]
            result.status = 200
            result.data = []
            json.each {
                def resp = add_one(it, false)
                if (resp)
                    result.data << resp
            }
            responseResult(result)
        } else {
           responseResult(add_one(json))
        }
    }
    private def add_one(json, shouldResponse = true) {
        print "json="+json
        try {
            if(!json.project || json.isNull('project')) {
                log.debug "No project was set"
                ImageInstance image = ImageInstance.read(json.image)
                log.debug "Get image = "+image
                log.debug "Get poroject = "+image.project
                if(image) json.project = image.project.id
                log.debug "Get poroject 2 = "+json.project
            }
            log.debug "json.project="+json.project + " (" + json.isNull('project') + ")"
            log.debug "json.location="+json.location + " (" + json.isNull('location') + ")"
            if(json.isNull('project')) throw new WrongArgumentException("Annotation must have a valide project:"+json.project)
            if(json.isNull('location')) {
                log.debug "json location is null!"
                throw new WrongArgumentException("Annotation must have a valide geometry:"+json.location)
            }

            annotationService.checkAuthorization(Long.parseLong(json.project.toString()), new Annotation())
            def result = annotationService.add(json)
            if (shouldResponse) responseResult(result)
            else return result
        } catch (CytomineException e) {
            log.error("add error:" + e.msg)
            log.error(e)
            if (shouldResponse) response([success: false, errors: e.msg], e.code)
            return null
        }
    }

    def update= {
        def json = request.JSON
        try {
            def domain = annotationService.retrieve(json)

            def result = annotationService.update(domain,json)
            responseResult(result)
        } catch (CytomineException e) {
            log.error(e)
            response([success: false, errors: e.msg], e.code)
        }
    }


    def delete = {
        def json = JSON.parse("{id : $params.id}")
        delete(annotationService, json)
    }
}
