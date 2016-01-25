/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.common.lib.to;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.apache.syncope.common.lib.AbstractBaseBean;
import org.apache.syncope.common.lib.types.IntMappingType;
import org.apache.syncope.common.lib.types.MappingPurpose;

@XmlRootElement(name = "mappingItem")
@XmlType
public class MappingItemTO extends AbstractBaseBean implements EntityTO<Long> {

    private static final long serialVersionUID = 2983498836767176862L;

    private Long key;

    /**
     * Attribute schema to be mapped. Consider that we can associate tha same attribute schema more than once, with
     * different aliases, to different resource attributes.
     */
    private String intAttrName;

    /**
     * Schema type to be mapped.
     */
    private IntMappingType intMappingType;

    /**
     * External resource's field to be mapped.
     */
    private String extAttrName;

    /**
     * Specify if the mapped target resource's field is the key.
     */
    private boolean connObjectKey;

    /**
     * Specify if the mapped target resource's field is the password.
     */
    private boolean password;

    /**
     * Specify if the mapped target resource's field is nullable.
     */
    private String mandatoryCondition = "false";

    /**
     * Mapping purposes.
     */
    private MappingPurpose purpose;

    private final List<String> mappingItemTransformerClassNames = new ArrayList<>();

    public boolean isConnObjectKey() {
        return connObjectKey;
    }

    public void setConnObjectKey(final boolean connObjectKey) {
        this.connObjectKey = connObjectKey;
    }

    public String getExtAttrName() {
        return extAttrName;
    }

    public void setExtAttrName(final String extAttrName) {
        this.extAttrName = extAttrName;
    }

    @Override
    public Long getKey() {
        return key;
    }

    @Override
    public void setKey(final Long key) {
        this.key = key;
    }

    public String getMandatoryCondition() {
        return mandatoryCondition;
    }

    public void setMandatoryCondition(final String mandatoryCondition) {
        this.mandatoryCondition = mandatoryCondition;
    }

    public boolean isPassword() {
        return password;
    }

    public void setPassword(final boolean password) {
        this.password = password;
    }

    public String getIntAttrName() {
        return intAttrName;
    }

    public void setIntAttrName(final String intAttrName) {
        this.intAttrName = intAttrName;
    }

    public IntMappingType getIntMappingType() {
        return intMappingType;
    }

    public void setIntMappingType(final IntMappingType intMappingType) {
        this.intMappingType = intMappingType;
    }

    public MappingPurpose getPurpose() {
        return purpose;
    }

    public void setPurpose(final MappingPurpose purpose) {
        this.purpose = purpose;
    }

    public List<String> getMappingItemTransformerClassNames() {
        return mappingItemTransformerClassNames;
    }

}
