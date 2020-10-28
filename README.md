# bug-9158

this project demonsrates Spring Security Bug #9158

Security configuration adds filter granting user with ADMIN role, role hierarchy with `ROLE_ADMIN > ROLE_USER` and three endpoints showing that:

 - /admin mapped with `@Secured` works for granted ADMIN role
 - /user mapped with `@Secured` **DOES NOT** work for USER role granted via hierarchy
 - /userPre mapped with `@PreAuth` with spel `hasRole(USER)` works as supposed via hierarchy
 
probably just exchanging `RoleVoter` with `RoleHierarchyVoter` will do the trick, but I'm not sure what about regression
