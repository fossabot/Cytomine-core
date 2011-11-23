package be.cytomine.command

import be.cytomine.Exception.ConstraintException
import be.cytomine.Exception.CytomineException
import grails.converters.JSON

/**
 * Created by IntelliJ IDEA.
 * User: lrollus
 * Date: 14/04/11
 * Time: 13:43
 * To change this template use File | Settings | File Templates.
 */
class EditCommand extends Command {

    protected createMessage(def updatedTerm, def params) {
        responseService.createMessage(updatedTerm, params, "Edit")
    }

    /**
     * Create undo message for an undo-edit on object
     * @param data New json value of object
     * @param object Undo-edit object
     * @param messageParams Params for result message
     * @return Result message
     */
    def createUndoMessage(def data, def object, Object[] messageParams) {
        log.info "createUndoMessage"
        this.createUndoMessage(data, object, messageParams, null);
    }

    /**
     * Create undo message for an undo-edit on object
     * @param data New json value of object
     * @param object Undo-edit object
     * @param messageParams Params for result message
     * @param additionalCallbackParams Additional params for callback (like imageID for annotation)
     * @return Result message
     */
    def createUndoMessage(def data, def object, Object[] messageParams, HashMap<String, Object> additionalCallbackParams) {
        String objectName = getClassName(object)
        log.info("Undo EditCommand " + objectName)
        String command = "be.cytomine.Edit" + objectName + "Command"
        String idName = objectName.toLowerCase() + "ID" //termID, annotationID,...

        log.debug("Edit " + objectName + " with id:" + id)

        HashMap<String, Object> paramsCallback = new HashMap<String, Object>()
        paramsCallback.put('method', command)
        paramsCallback.put(idName, id)
        if (additionalCallbackParams)
            paramsCallback.putAll(additionalCallbackParams);

        def message = messageSource.getMessage(command, messageParams as Object[], Locale.ENGLISH)

        HashMap<String, Object> params = new HashMap<String, Object>()
        params.put('message', message)
        params.put('callback', paramsCallback)
        params.put('printMessage', printMessage)
        params.put(objectName.toLowerCase(), id)

        return [data: params, status: 200]
    }

    /**
     * Create redo message for an redo-edit on object
     * @param data New json value of object
     * @param object Redo-edit object
     * @param messageParams Params for result message
     * @return Result message
     */
    def createRedoMessage(def data, def object, Object[] messageParams) {
        this.createRedoMessage(data, object, messageParams, null)
    }

    /**
     * Create redo message for an redo-edit on object
     * @param data New json value of object
     * @param object Redo-edit object
     * @param messageParams Params for result message
     * @param additionalCallbackParams Additional params for callback (like imageID for annotation)
     * @return Result message
     */
    def createRedoMessage(def data, def object, Object[] messageParams, HashMap<String, Object> additionalCallbackParams) {

        String objectName = getClassName(object)
        String command = "be.cytomine.Edit" + objectName + "Command"
        String idName = objectName.toLowerCase() + "ID" //termID, annotationID,...

        log.debug("Edit " + objectName + " with id:" + id)

        HashMap<String, Object> paramsCallback = new HashMap<String, Object>()
        paramsCallback.put('method', command)
        paramsCallback.put(idName, object.id)
        if (additionalCallbackParams)
            paramsCallback.putAll(additionalCallbackParams);

        def message = messageSource.getMessage(command, messageParams, Locale.ENGLISH)


        HashMap<String, Object> params = new HashMap<String, Object>()
        params.put('message', message)
        params.put('callback', paramsCallback)
        params.put('printMessage', printMessage)
        params.put(objectName.toLowerCase(), object)

        def result = [data: params, status: 200];

        return result
    }

    protected void fillCommandInfo(def newObject,def oldObject, String message) {
        HashMap<String, Object> paramsData = new HashMap<String, Object>()
        paramsData.put('previous' + responseService.getClassName(newObject), (JSON.parse(oldObject)))
        paramsData.put("new" + responseService.getClassName(newObject), newObject)
        data = (paramsData) as JSON
        actionMessage = message
    }

}
