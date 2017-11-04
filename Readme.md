## Simple authentication and authorization example with passport, node_acl, MongoDB and expressjs(v4.x)
> The example shown here uses local userdata and sessions to remember a
 logged in user. Roles are persistent all the way and applied to user
 after logging in.

### Usage:
 1. Install dependencies with `npm i`.
 2. Start this as server by running `npm start`. Make sure mongo is also running.
 3. Play with the resoures.
 
    **Login via GET**
     http://localhost:3500/login?username=bob&password=secret

    **Logout**
     http://localhost:3500/logout

    **Check your current user and roles**
     http://localhost:3500/status

    **Only visible for users and higher**
     http://localhost:3500/secret

    **Manage roles**
    user is either 1 or 2 and role is either 'guest', 'user' or 'admin'
     http://localhost:3500/allow/:user/:role
     http://localhost:3500/disallow/:user/:role


### Explanation:
 * Passport is used to **authenticate** a user.
 * Acl is used to **authorize** a user.
 * There are two users present in memory. You can login as either one of them.
 * When you first start a server, a *logged in user* has *no role*.
 * Such user cannot access any *resources*. You can check this at http://localhost:3500/secret.
 * In our code, there are three roles - *admin, user, guest* .
 * User can do anything that guest can do (Using `acl.addRoleParents('user', 'guest')`)
 * Admin can do anything that user can do. (Using `acl.addRoleParents('admin', 'user')`)
 * Also admin can do *anything* with **secret** resource.
 * A user can only *get* the **secret** resource.
 * A guest can do nothing.
 * To assign an authenticated(logged in) user a role, we use `acl.addUserRoles(userId, role)` method. This is wrapped in http://localhost:3500/allow/:user/:role.
    Try out - http://localhost:3500/allow/1/user. 
