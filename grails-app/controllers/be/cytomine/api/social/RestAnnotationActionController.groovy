package be.cytomine.api.social

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

import be.cytomine.Exception.CytomineException
import be.cytomine.Exception.ObjectNotFoundException
import be.cytomine.api.RestController
import be.cytomine.image.ImageInstance
import be.cytomine.security.User
import org.restapidoc.annotation.RestApi
import org.restapidoc.annotation.RestApiMethod
import org.restapidoc.annotation.RestApiParam
import org.restapidoc.annotation.RestApiParams
import org.restapidoc.pojo.RestApiParamType


@RestApi(name = "Social | annotation action services", description = "Methods to manage actions performed on annotations")
class RestAnnotationActionController extends RestController {

    def annotationActionService
    def imageInstanceService
    def secUserService

    @RestApiMethod(description="Record an action performed by a user on an annotation.")
    @RestApiParams(params=[
    @RestApiParam(name="annotationIdent", type="long", paramType = RestApiParamType.QUERY, description = "The annotation id"),
    @RestApiParam(name="action", type="string", paramType = RestApiParamType.QUERY, description = "The action"),
    ])
    def add() {
        try {
            responseSuccess(annotationActionService.add(request.JSON))
        } catch (CytomineException e) {
            log.error(e)
            response([success: false, errors: e.msg], e.code)
        }
    }

    @RestApiMethod(description="Summarize the annotation actions entries.")
    @RestApiParams(params=[
    @RestApiParam(name="image", type="long", paramType = RestApiParamType.PATH, description = "The image id"),
    @RestApiParam(name="user", type="long", paramType = RestApiParamType.QUERY, description = "The user id", required=false),
    @RestApiParam(name="afterThan", type="long", paramType = RestApiParamType.QUERY, description = "A date. Will select all the entries created after this date", required=false),
    @RestApiParam(name="beforeThan", type="long", paramType = RestApiParamType.QUERY, description = "A date. Will select all the entries created before this date", required=false),
    ])
    def list() {
        ImageInstance image = imageInstanceService.read(params.image)
        User user = secUserService.read(params.user)
        if(params.user != null && user == null) throw new ObjectNotFoundException("Invalid user")

        Long afterThan = params.long("afterThan")
        Long beforeThan = params.long("beforeThan")
        responseSuccess(annotationActionService.list(image, user, afterThan, beforeThan))
    }
}
