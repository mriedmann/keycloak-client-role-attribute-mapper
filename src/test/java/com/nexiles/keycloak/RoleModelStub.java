package com.nexiles.keycloak;

import com.webauthn4j.util.exception.NotImplementedException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.*;
import java.util.stream.Stream;

class RoleModelStub implements RoleModel {
    private String name;
    private String description;
    private final String id = String.valueOf(UUID.randomUUID());
    private final List<RoleModel> childRoles = new ArrayList<>();
    private final Map<String, List<String>> attributes = new HashMap<>();
    private final RoleContainerModel container;

    RoleModelStub(String name, String description, RoleContainerModel container) {
        this.name = name;
        this.description = description;
        this.container = container;
    }

    RoleModelStub(String name, String description) {
        this(name, description, null);
    }

    RoleModelStub(String name, RoleContainerModel container) {
        this(name, "", container);
    }

    RoleModelStub(String name) {
        this(name, "");
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public boolean isComposite() {
        return !childRoles.isEmpty();
    }

    @Override
    public void addCompositeRole(RoleModel role) {
        childRoles.add(role);
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        childRoles.remove(role);
    }

    @Override
    public Stream<RoleModel> getCompositesStream() {
        return childRoles.stream();
    }

    @Override
    public Stream<RoleModel> getCompositesStream(String search, Integer first, Integer max) {
        throw new NotImplementedException();
    }

    @Override
    public boolean isClientRole() {
        return this.container instanceof ClientModel;
    }

    @Override
    public String getContainerId() {
        return this.container.getId();
    }

    @Override
    public RoleContainerModel getContainer() {
        return this.container;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        throw new NotImplementedException();
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        if (attributes.containsKey(name)){
            attributes.get(name).add(value);
        } else {
            attributes.put(name,  new ArrayList<>(List.of(value)));
        }
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        attributes.put(name, values);
    }

    @Override
    public void removeAttribute(String name) {
        attributes.remove(name);
    }

    @Override
    public String getFirstAttribute(String name) {
        return RoleModel.super.getFirstAttribute(name);
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return attributes.keySet().stream();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return attributes;
    }
}
