package be.cytomine.utils

import groovy.sql.Sql
import org.codehaus.groovy.grails.commons.ApplicationHolder as AH
import grails.util.Holders

/**
 * A task provide info about a command.
 * The main info is the progress status
 * THIS CLASS CANNOT BE A DOMAIN! Because it cannot works with hibernate transaction.
 */
class Task {

    Long id
    /**
     * Request progress between 0 and 100
     */
    int progress = 0

    /**
     * Project updated by the command task
     */
    Long projectIdent = -1

    /**
     * User that ask the task
     */
    Long userIdent


    def sequenceService


    def getMap() {
        def map = [:]
        map.id = id
        map.progress = progress
        map.project = projectIdent
        map.user = userIdent
        map.comments = getLastComments(5)
        return map
    }

    def getLastComments(int max) {
        //sql request retrieve n last comments for task
        def data = []
        Sql sql = createSQLDB()
        sql.eachRow("SELECT comment FROM task_comment where taskIdent = ${id} order by timestamp desc limit $max") {
            data << it[0]
        }
        closeSQL(sql)
        data
    }

    Task saveOnDatabase() {
        println AH.application.mainContext.dataSource
        boolean isAlreadyInDatabase = false
        Sql sql = createSQLDB()
        sql.eachRow("SELECT id FROM task where id = ${id}") {
            isAlreadyInDatabase = true
        }

        if(!isAlreadyInDatabase) {
            id = AH.application.mainContext.sequenceService.generateID()
            sql.executeInsert("INSERT INTO task (id,progress,project_id,user_id) VALUES ($id,$progress,$projectIdent,$userIdent)")
        } else {
            sql.executeUpdate("UPDATE task set progress=${progress} WHERE id=$id")
            println "UPDATE task set progress=${progress} WHERE id=$id"
            println getFromDatabase(id).progress
        }
        closeSQL(sql)
        getFromDatabase(id)

    }

    def getFromDatabase(def id) {
        Task task = null
        Sql sql = createSQLDB()
        sql.eachRow("SELECT id,progress,project_id,user_id FROM task where id = ${id}") {
            task = new Task()
            task.id = it[0]
            task.progress = it[1]
            task.projectIdent = it[2]
            task.userIdent = it[3]
        }
        closeSQL(sql)
        return task
    }

    def addComment(String comment) {
        if(comment!=null && !comment.equals("")) {
            TaskComment taskComment = new TaskComment(taskIdent: id,comment: comment,timestamp: new Date().getTime())
            taskComment.saveOnDatabase()
        }
    }


    static Sql createSQLDB() {
        def db = [url:Holders.config.dataSource.url, user:Holders.config.dataSource.username, password:Holders.config.dataSource.password, driver:Holders.config.dataSource.driverClassName]
        def sql = Sql.newInstance(db.url, db.user, db.password, db.driver)
        return sql
    }

    static closeSQL(Sql sql) {
        sql.close()
    }

}