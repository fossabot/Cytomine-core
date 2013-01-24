package be.cytomine.command

import be.cytomine.Exception.CytomineException
import be.cytomine.Exception.TooLongRequestException
import org.codehaus.groovy.grails.web.json.JSONElement

class CommandService {

    def springSecurityService
    def grailsApplication

    static final int SUCCESS_ADD_CODE = 200
    static final int SUCCESS_EDIT_CODE = 200
    static final int SUCCESS_DELETE_CODE = 200

    static final int NOT_FOUND_CODE = 404
    static final int TOO_LONG_REQUEST = 413

    /**
     * Execute an 'addcommand' c with json data
     * Store command in undo stack if necessary and in command history
     */
    def processCommand(AddCommand c, JSONElement json) throws CytomineException {
        processCommand(c, json, SUCCESS_ADD_CODE)
    }

    /**
     * Execute an 'editcommand' c with json data
     * Store command in undo stack if necessary and in command history
     */
    def processCommand(EditCommand c, JSONElement json) throws CytomineException {
        processCommand(c, json, SUCCESS_EDIT_CODE)
    }

    /**
     * Execute a 'deletecommand' c with json data
     * Store command in undo stack if necessary and in command history
     */
    def processCommand(DeleteCommand c, JSONElement json) throws CytomineException {
        processCommand(c, json, SUCCESS_DELETE_CODE)
    }

    /**
     * Execute a 'command' c with json data
     * Store command in undo stack if necessary and in command history
     * if success, put http response code as successCode
     */
    def processCommand(Command c, JSONElement json, int successCode) throws CytomineException {
        log.debug "processCommand: ${c.class}:" + json
        c.setJson(json)
        String postData = json.toString()
        def maxRequestSize = grailsApplication.config.cytomine.maxRequestSize

        //check if request data are not too big
        if (postData.size() >= maxRequestSize) {
            log.error "c.postData.size() is too big=" + postData.size() + " Command.MAXSIZEREQUEST=" + maxRequestSize
            throw new TooLongRequestException("Request is too long")
        }

        //execute command
        def result = c.execute()
        if (result.status == successCode) {
            if (!c.validate()) {
                log.error c.errors.toString()
            }
            c.save()
            CommandHistory ch = new CommandHistory(command: c, prefixAction: "", project: c.project)
            ch.save();
            if (c.saveOnUndoRedoStack) {
                new UndoStackItem(command: c, user: c.user, transaction: c.transaction).save(flush: true)
            }
        }
        log.debug "result.status=" + result.status
        return result
    }
}
