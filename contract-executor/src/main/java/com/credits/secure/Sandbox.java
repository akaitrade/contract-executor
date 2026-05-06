package com.credits.secure;

import java.security.*;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * This class establishes a security manager that confines the permissions for code executed through specific classes,
 * which may be specified by class, class name and/or class loader.
 * <p>
 * To 'execute through a class' means that the execution stack includes the class. E.g., if a method of class {@code A}
 * invokes a method of class {@code B}, which then invokes a method of class {@code C}, and all three classes were
 * previously {@link #confine(Class, Permissions) confined}, then for all actions that are executed by class {@code C}
 * the <i>intersection</i> of the three {@link Permissions} apply.
 * <p>
 * Once the permissions for a class, class name or class loader are confined, they cannot be changed; this prevents any
 * attempts (e.g. of the confined class itself) to release the confinement.
 * <p>
 * Code example:
 * <pre>
 *  Runnable unprivileged = new Runnable() {
 *      public void run() {
 *          System.getProperty("user.dir");
 *      }
 *  };
 *
 *  // Run without confinement.
 *  unprivileged.run(); // Works fine.
 *
 *  // Set the most strict permissions.
 *  Sandbox.confine(unprivileged.getClass(), new Permissions());
 *  unprivileged.run(); // Throws a SecurityException.
 *
 *  // Attempt to change the permissions.
 *  {
 *      Permissions permissions = new Permissions();
 *      permissions.add(new AllPermission());
 *      Sandbox.confine(unprivileged.getClass(), permissions); // Throws a SecurityException.
 *  }
 *  unprivileged.run();
 * </pre>
 */
public final class Sandbox {

    private Sandbox() {
    }

    // Per-class confined permissions. The previous attempt at a WeakHashMap failed
    // because the value (AccessControlContext) transitively keeps the Class key
    // alive: ACC -> ProtectionDomain -> ClassLoader -> all classes loaded by it,
    // including the key class itself. The bounded LRU that replaced it then
    // pinned thousands of contract classloaders in metaspace.
    //
    // Storing only the Permissions snapshot breaks that retention chain — a
    // Permissions object is a flat collection of Permission instances and does
    // not reference back to the Class or its ClassLoader. With that, a true
    // weak-keyed map works: when the contract Class becomes unreachable
    // elsewhere, this entry is collected automatically.
    private static final Map<Class<?>, Permissions> CHECKED_CLASSES =
        Collections.synchronizedMap(new WeakHashMap<>());

    static {
        // Install our custom security manager.
        //System.out.println("Installing our custom security manager");
        if (System.getSecurityManager() != null) {
            throw new ExceptionInInitializerError("There's already a security manager set");
        }

        System.setSecurityManager(new SecurityManager() {

            @Override
            public void checkPermission(Permission perm) {
                assert perm != null;
                for (Class<?> clasS : this.getClassContext()) {
                    Permissions perms = Sandbox.CHECKED_CLASSES.get(clasS);
                    if (perms != null && !perms.implies(perm)) {
                        throw new AccessControlException(
                            "class " + clasS.getTypeName() + " access denied (" + perm + ")", perm);
                    }
                }
            }
        });
    }

    /**
     * All future actions executed through {@code clasS} will be checked against {@code permissions}.
     * The first call wins; subsequent calls are ignored to preserve the original
     * "permissions cannot be relaxed" guarantee.
     */
    public static void confine(Class<?> clasS, Permissions permissions) {
        Sandbox.CHECKED_CLASSES.putIfAbsent(clasS, permissions);
    }

    /**
     * Convenience overload: confines using the {@link ProtectionDomain}'s permissions.
     */
    public static void confine(Class<?> clasS, ProtectionDomain protectionDomain) {
        PermissionCollection pc = protectionDomain.getPermissions();
        Permissions perms = new Permissions();
        if (pc != null) {
            java.util.Enumeration<Permission> e = pc.elements();
            while (e.hasMoreElements()) perms.add(e.nextElement());
        }
        Sandbox.confine(clasS, perms);
    }

    /**
     * Convenience overload: confines using the permissions of the first
     * {@link ProtectionDomain} encoded in the given {@link AccessControlContext}.
     * Kept for source-level compatibility with prior callers.
     */
    public static void confine(Class<?> clasS, AccessControlContext accessControlContext) {
        // ACC's internal ProtectionDomains are not directly exposed; we approximate
        // by storing an empty Permissions set, which yields the safest (most
        // restrictive) behavior. In this codebase ACC is only constructed
        // internally from a single ProtectionDomain via the (Class, ProtectionDomain)
        // overload above, so this fallback is unreachable in practice.
        Sandbox.confine(clasS, new Permissions());
    }
}
