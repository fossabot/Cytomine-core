package be.cytomine

import static org.springframework.security.acls.domain.BasePermission.ADMINISTRATION
import org.springframework.security.acls.model.Acl

import org.springframework.security.acls.model.NotFoundException

import be.cytomine.security.SecUser
import be.cytomine.security.User
import be.cytomine.project.Project
import org.codehaus.groovy.grails.plugins.springsecurity.acl.AclObjectIdentity
import org.codehaus.groovy.grails.plugins.springsecurity.acl.AclClass
import org.codehaus.groovy.grails.plugins.springsecurity.acl.AclEntry
import org.codehaus.groovy.grails.plugins.springsecurity.acl.AclSid

class SecurityService {

    def aclUtilService

    def transactional = false

    static transaction = false

    def serviceMethod() {

    }

    User getCreator(def domain) {
        List<User> users = SecUser.executeQuery("select secUser from AclObjectIdentity as aclObjectId, AclSid as aclSid, SecUser as secUser where aclObjectId.objectId = "+domain.id+" and aclObjectId.owner = aclSid.id and aclSid.sid = secUser.username and secUser.class = 'be.cytomine.security.User'")
        User user = users.isEmpty() ? null : users.first()
        return user
    }

    List<SecUser> getAdminList(def domain) {

        def users = SecUser.executeQuery("select distinct secUser from AclObjectIdentity as aclObjectId, AclEntry as aclEntry, AclSid as aclSid, SecUser as secUser "+
            "where aclObjectId.objectId = "+domain.id+" and aclEntry.aclObjectIdentity = aclObjectId.id and aclEntry.mask = 16 and aclEntry.sid = aclSid.id and aclSid.sid = secUser.username and secUser.class = 'be.cytomine.security.User'")

        return users
    }

    //@Transactional(noRollbackFor = NotFoundException.class)

    List<SecUser> getUserList(def domain) {
        List<SecUser> users = SecUser.executeQuery("select distinct secUser from AclObjectIdentity as aclObjectId, AclEntry as aclEntry, AclSid as aclSid, SecUser as secUser "+
            "where aclObjectId.objectId = "+domain.id+" and aclEntry.aclObjectIdentity = aclObjectId.id and aclEntry.sid = aclSid.id and aclSid.sid = secUser.username and secUser.class = 'be.cytomine.security.User'")

        return users
    }

    List<Project> getProjectList(SecUser user) {
        AclClass aclClassProject = AclClass.findByClassName('be.cytomine.project.Project')
        Collection<AclEntry> aclEntries = AclEntry.findAllBySid(AclSid.findBySid(user.getUsername()))
        List<AclObjectIdentity> aclObjectIdentities = AclObjectIdentity.createCriteria().list {
            eq('aclClass', aclClassProject)
            inList('id', aclEntries.collect{it.aclObjectIdentity.id})
        }
        return Project.createCriteria().list() {
            inList("id", aclObjectIdentities.collect{it.objectId})
        }
    }

}
