import com.sample.Role
import com.sample.User
import com.sample.UserRole

class BootStrap {

    def init = { servletContext ->
        def adminRole = new Role('ADMIN').save()
        def userRole = new Role('USER').save()

        def testUser = new User('me', 'password').save()

        UserRole.create testUser, adminRole

        UserRole.withSession {
            it.flush()
            it.clear()
        }

        assert User.count() == 1
        assert Role.count() == 2
        assert UserRole.count() == 1
    }
    def destroy = {
    }
}
