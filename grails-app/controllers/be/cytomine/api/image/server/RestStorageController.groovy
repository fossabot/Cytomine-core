package be.cytomine.api.image.server

/*
* Copyright (c) 2009-2017. Authors: see NOTICE file.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import be.cytomine.Exception.AlreadyExistException
import be.cytomine.Exception.CytomineException
import be.cytomine.api.RestController
import be.cytomine.image.Mime
import be.cytomine.image.server.ImageServer
import be.cytomine.image.server.ImageServerStorage
import be.cytomine.image.server.MimeImageServer
import be.cytomine.image.server.Storage
import be.cytomine.security.SecUser
import be.cytomine.security.User
import grails.converters.JSON
import org.restapidoc.annotation.RestApi
import org.restapidoc.annotation.RestApiMethod
import org.restapidoc.annotation.RestApiParam
import org.restapidoc.annotation.RestApiParams
import org.restapidoc.pojo.RestApiParamType

@RestApi(name="Image | server | storage services", description="Methods to manage storages")
class RestStorageController extends RestController {

    def cytomineService
    def storageService
    def secUserService

    @RestApiMethod(description="List all storages", listing=true)
    def list() {
        log.info 'listing storages'
        responseSuccess(storageService.list())
    }

    @RestApiMethod(description="List all storages for the current user and the provided mime type", listing=true)
    @RestApiParams(params=[
            @RestApiParam(name="mimeType", type="String", paramType = RestApiParamType.QUERY, description = "The mime type")
    ])
    def listByMime() {
        log.info 'listing storages by mime/user'
        def currentUser = cytomineService.currentUser

        String mimeType = params.get('mimeType')
        Mime mime = Mime.findByMimeType(mimeType)

        //list all images server for this mime
        List<ImageServer> servers = MimeImageServer.findAllByMime(mime).collect{
            it.imageServer
        }

        //list all storage for this user
        List<Storage> storages = Storage.findAllByUser(currentUser)

        if(servers.isEmpty()) {
            responseNotFound("ImageServer", "No image server found for mimeType=$mimeType")
        } else if(storages.isEmpty()) {
            responseNotFound("Storage", "No storage for user=${currentUser.id}")
        } else {
            def serverAvailableForUser = ImageServerStorage.findAllByImageServerInListAndStorageInList(servers,storages)
            if(serverAvailableForUser.isEmpty()) {
                responseNotFound("ImageServerStorage", "No imageserver-storage found for servers=${servers} and storages=${storages}")
            } else {
                responseSuccess(serverAvailableForUser)
            }
        }
    }

    @RestApiMethod(description="Get a storage")
    @RestApiParams(params=[
            @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH, description = "The storage id")
    ])
    def show() {
        Storage storage = storageService.read(params.long('id'))
        if (storage) {
            responseSuccess(storage)
        } else {
            responseNotFound("Storage", params.id)
        }
    }

    @RestApiMethod(description="Add a new storage")
    def add() {
        add(storageService, request.JSON)
    }

    @RestApiMethod(description="Update a storage")
    @RestApiParams(params=[
            @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH, description = "The storage id")
    ])
    def update() {
        try {
            def domain = storageService.retrieve(request.JSON)
            def result = storageService.update(domain,request.JSON)
            responseResult(result)
        } catch (CytomineException e) {
            log.error(e)
            response([success: false, errors: e.msg], e.code)
        }
    }

    @RestApiMethod(description="Delete a storage")
    @RestApiParams(params=[
            @RestApiParam(name="id", type="long", paramType = RestApiParamType.PATH, description = "The storage id")
    ])
    def delete() {
        try {
            def domain = storageService.retrieve(JSON.parse("{id : $params.id}"))
            def result = storageService.delete(domain,transactionService.start(),null,true)
            responseResult(result)
        } catch (CytomineException e) {
            log.error(e)
            response([success: false, errors: e.msg], e.code)
        }
    }

    /**
     * Create a storage for user with default parameters
     */
    @RestApiMethod(description="Create a storage for a user with default parameter values")
    @RestApiParams(params=[
            @RestApiParam(name="user", type="long", paramType = RestApiParamType.PATH, description = "The user id")
    ])
    def create() {
        def id = params.long('user')
        SecUser user = secUserService.read(id)
        if (user instanceof User) {
            if (Storage.findByUser(user)) {
                new AlreadyExistException("A storage already exists for user $user.username")
            } else {
                storageService.initUserStorage((User)user)
                responseSuccess(Storage.findByUser(user))
            }
        }
    }
}
