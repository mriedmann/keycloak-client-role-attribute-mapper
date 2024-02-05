package com.nexiles.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.JsonUtils;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.util.*;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserClientRoleAttributeMappingMapperTest {


    @Test
    void mapClaimWithSingleAttribute(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        final String tokenClaimName = "rules";
        final String attributeName = "attr1";
        final String roleName = "rolename";

        Map<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "rules",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME, roleName,
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME, attributeName
        );
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        UserClientRoleAttributeMappingMapper.ClientRoleAttributes clientRoleAttributes = new UserClientRoleAttributeMappingMapper.ClientRoleAttributes(
                "clientid",
                roleName,
                parseJsonObject("{\"attr1\":[\"attr1value1\"]}")
        );
        UserClientRoleAttributeMappingMapper.mapClaim(token, mappingModel, clientRoleAttributes);

        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("attr1value1", traverseClaimMap(claims, tokenClaimName + ".clientid.rolename." + attributeName));
    }

    @Test
    void mapClaimWithSingeAttributeAndMultipleValue(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        final String tokenClaimName = "rules";
        final String attributeName = "attr1";
        final String roleName = "rolename";

        Map<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        Map<String, String> config = Map.of(
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "rules",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_CLIENT_ID, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ATTRIBUTE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_ATTRIBUTE_MAPPING_ADD_ROLE_NAME, "true",
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_NAME, roleName,
                UserClientRoleAttributeMappingMapper.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ROLE_ATTRIBUTE_NAME, attributeName
        );
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        UserClientRoleAttributeMappingMapper.ClientRoleAttributes clientRoleAttributes = new UserClientRoleAttributeMappingMapper.ClientRoleAttributes(
                "clientid",
                roleName,
                parseJsonObject("{\"attr1\":[\"attr1value1\",\"attr1value2\"]}")
        );
        UserClientRoleAttributeMappingMapper.mapClaim(token, mappingModel, clientRoleAttributes);

        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("attr1value1", traverseClaimMap(claims, tokenClaimName + ".clientid.rolename." + attributeName));
    }

    static RoleModel createRole(ClientModel clientModel, String name, String attributesJson) {
        RoleModel role = new RoleModelStub(name, clientModel);
        Map<String, List<String>> attributes = parseJsonObject(attributesJson);
        attributes.forEach(role::setAttribute);
        return role;
    }

    static List<String> getAttr(List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes, String clientId, String roleName, String attributeName) {
        Optional<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> first = filteredAttributes.stream()
                .filter(clientRoleAttributes -> clientRoleAttributes.clientId().equals(clientId))
                .filter(clientRoleAttributes -> clientRoleAttributes.roleName().equals(roleName))
                .findFirst();
        if (first.isEmpty())
            throw new RuntimeException(String.format("roleName '%s' '%s' '%s' not found", clientId, roleName, attributeName));
        return first.get().attributes().getOrDefault(attributeName, new ArrayList<>());
    }

    static class RoleGen {
        static final String clientId1 = "clientId1";
        static final String clientId2 = "clientId2";
        static final String roleName1 = "rs_dataset0001_role1";
        static final String roleName2 = "rs_dataset0001_role2";
        static List<RoleModel> getRoles(ClientModel client1, ClientModel client2) {
            when(client1.getClientId()).then(invocationOnMock -> clientId1);
            when(client2.getClientId()).then(invocationOnMock -> clientId2);
            return new ArrayList<>(List.of(
                    createRole(client1, roleName1, "{\"a1\":[\"r1a1v1\"],\"a2\":[\"r1a2v1\",\"r1a2v2\"],\"b1\":[\"r1b1v1\"]}"),
                    createRole(client1, roleName2, "{\"a1\":[\"r2a1v1\",\"r2a1v2\"],\"a2\":[\"r2a2v1\"],\"b1\":[\"r2b1v1\"]}"),
                    createRole(client2, roleName1, "{\"a1\":[\"r1a1v1\"],\"a2\":[\"r1a2v1\",\"r1a2v2\"],\"b1\":[\"r1b1v1\"]}"),
                    createRole(client2, roleName2, "{\"a1\":[\"r2a1v1\",\"r2a1v2\"],\"a2\":[\"r2a2v1\"],\"b1\":[\"r2b1v1\"]}")
            ));
        }


    }

    static void assertFilteredAttributes(List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes, String clientId, String roleName, String attributeName, Boolean negate){
        BiConsumer<String, String> assertFunction;
        if (negate) {
            assertFunction = Assertions::assertNotEquals;
        } else {
            assertFunction = Assertions::assertEquals;
        }
        if (roleName == null || roleName.equals(RoleGen.roleName1)) {
            if(attributeName == null || attributeName.equals("a1")) assertFunction.accept("r1a1v1", getAttr(filteredAttributes, clientId, RoleGen.roleName1, "a1").stream().skip(0).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("a2")) assertFunction.accept("r1a2v1", getAttr(filteredAttributes, clientId, RoleGen.roleName1, "a2").stream().skip(0).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("a2")) assertFunction.accept("r1a2v2", getAttr(filteredAttributes, clientId, RoleGen.roleName1, "a2").stream().skip(1).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("b1")) assertFunction.accept("r1b1v1", getAttr(filteredAttributes, clientId, RoleGen.roleName1, "b1").stream().skip(0).findFirst().orElse(null));
        }
        if (roleName == null || roleName.equals(RoleGen.roleName2)) {
            if(attributeName == null || attributeName.equals("a1")) assertFunction.accept("r2a1v1", getAttr(filteredAttributes, clientId, RoleGen.roleName2, "a1").stream().skip(0).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("a1")) assertFunction.accept("r2a1v2", getAttr(filteredAttributes, clientId, RoleGen.roleName2, "a1").stream().skip(1).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("a2")) assertFunction.accept("r2a2v1", getAttr(filteredAttributes, clientId, RoleGen.roleName2, "a2").stream().skip(0).findFirst().orElse(null));
            if(attributeName == null || attributeName.equals("b1")) assertFunction.accept("r2b1v1", getAttr(filteredAttributes, clientId, RoleGen.roleName2, "b1").stream().skip(0).findFirst().orElse(null));
        }
    }

    @Test
    void getFilteredClientRoleAttributesWithoutAnyLimitations(@Mock ClientModel client1, @Mock ClientModel client2) {
        List<RoleModel> roles = RoleGen.getRoles(client1, client2);

        List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes = UserClientRoleAttributeMappingMapper.getFilteredClientRoleAttributes(
                roles.stream(),
                null,
                null,
                null,
                null
        ).stream().toList();

        assertEquals(4, filteredAttributes.size());
        for (String clientId: new String[]{RoleGen.clientId1,RoleGen.clientId2}) {
            assertFilteredAttributes(filteredAttributes, clientId, null, null, false);
        }
    }

    @Test
    void getFilteredClientRoleAttributesWithClientIdLimitation(@Mock ClientModel client1, @Mock ClientModel client2) {
        List<RoleModel> roles = RoleGen.getRoles(client1, client2);

        List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes = UserClientRoleAttributeMappingMapper.getFilteredClientRoleAttributes(
                roles.stream(),
                RoleGen.clientId1,
                null,
                null,
                null
        ).stream().toList();

        assertEquals(2, filteredAttributes.size());
        assertFilteredAttributes(filteredAttributes, RoleGen.clientId1, null, null, false);
    }

    @Test
    void getFilteredClientRoleAttributesWithRoleNameLimitations(@Mock ClientModel client1, @Mock ClientModel client2) {
        List<RoleModel> roles = RoleGen.getRoles(client1, client2);

        List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes = UserClientRoleAttributeMappingMapper.getFilteredClientRoleAttributes(
                roles.stream(),
                null,
                RoleGen.clientId1 + "." + RoleGen.roleName1,
                null,
                null
        ).stream().toList();

        assertEquals(1, filteredAttributes.size());
        assertFilteredAttributes(filteredAttributes, RoleGen.clientId1, RoleGen.roleName1, null, false);
    }

    @Test
    void getFilteredClientRoleAttributesWithAttributeNameLimitations(@Mock ClientModel client1, @Mock ClientModel client2) {
        List<RoleModel> roles = RoleGen.getRoles(client1, client2);

        List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes = UserClientRoleAttributeMappingMapper.getFilteredClientRoleAttributes(
                roles.stream(),
                null,
                null,
                "b1",
                null
        ).stream().toList();

        assertEquals(4, filteredAttributes.size());
        for (String clientId: new String[]{RoleGen.clientId1,RoleGen.clientId2}) {
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "b1", false);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "a1", true);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "a2", true);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName2, "b1", false);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName2, "a1", true);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName2, "a2", true);
        }
    }

    @Test
    void getFilteredClientRoleAttributesWithAttributeNamePrefixLimitations(@Mock ClientModel client1, @Mock ClientModel client2) {
        List<RoleModel> roles = RoleGen.getRoles(client1, client2);

        List<UserClientRoleAttributeMappingMapper.ClientRoleAttributes> filteredAttributes = UserClientRoleAttributeMappingMapper.getFilteredClientRoleAttributes(
                roles.stream(),
                null,
                null,
                null,
                "a"
        ).stream().toList();

        assertEquals(4, filteredAttributes.size());
        for (String clientId: new String[]{RoleGen.clientId1,RoleGen.clientId2}) {
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "a1", false);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "a2", false);
            assertFilteredAttributes(filteredAttributes, clientId, RoleGen.roleName1, "b1", true);
        }
    }

    private static <T> Map<String,T> parseJsonObject(String json) {
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<HashMap<String, T>> typeRef = new TypeReference<>(){};
        try {
            return mapper.readValue(json, typeRef);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private Object traverseClaimMap(Map<String,Object> claims, List<String> claimPathParts) {
        if(claims == null) throw new IllegalArgumentException("claims");
        String part = claimPathParts.remove(0);
        if(claimPathParts.isEmpty()) {
            // end of path
            return claims.get(part);
        }
        Object o = claims.get(part);
        if(o == null)
            throw new RuntimeException(String.format("invalid path %s", String.join(".", claimPathParts)));
        if(o instanceof Map)
            return traverseClaimMap((Map<String,Object>)o, claimPathParts);

        throw new RuntimeException(String.format("invalid value at path %s %s", String.join(".", claimPathParts), o));
    }

    private Object traverseClaimMap(Map<String,Object> claims, String path) {
        List<String> claimPathParts = JsonUtils.splitClaimPath(path);
        return traverseClaimMap(claims, claimPathParts);
    }

    @Test
    void mapToClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        HashMap<String, Object> claimStore = new HashMap<>();
        when(token.getOtherClaims()).then((Answer<Map<String, Object>>) invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingStringClaimWithMultivalued(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":\"2 == 2\"}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"2 == 2", "1 == 1"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }

    @Test
    void mapToClaimWithExistingListClaimWithMultivalued(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"3 == 3", "2 == 2", "1 == 1"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }

    @Test
    void mapToClaimWithExistingStringClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":\"2 == 2\"}}}");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingListClaim(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = "1 == 1";

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("1 == 1", traverseClaimMap(claims, tokenClaimName));
    }

    @Test
    void mapToClaimWithExistingListClaimAndArrayClaimValue(@Mock IDToken token, @Mock ProtocolMapperModel mappingModel) {
        Map<String, Object> claimStore = parseJsonObject("{\"clientname\":{\"rolename\":{\"rules\":[\"3 == 3\",\"2 == 2\"]}}}");
        Map<String, String> config = Map.of(ProtocolMapperUtils.MULTIVALUED, "true");
        when(token.getOtherClaims()).then(invocationOnMock -> claimStore);
        when(mappingModel.getConfig()).then(invocationOnMock -> config);

        String tokenClaimName = "clientname.rolename.rules";
        Object claimValue = Arrays.asList("1 == 1", "0 == 0");

        UserClientRoleAttributeMappingMapper.mapToClaim(token, mappingModel, tokenClaimName, claimValue);
        Map<String, Object> claims = token.getOtherClaims();
        assertArrayEquals(new String[]{"3 == 3", "2 == 2", "1 == 1", "0 == 0"}, ((ArrayList<String>)traverseClaimMap(claims, tokenClaimName)).toArray());
    }
}