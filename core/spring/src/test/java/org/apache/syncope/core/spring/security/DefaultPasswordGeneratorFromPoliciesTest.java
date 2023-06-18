package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.ImplementationLookup;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.utils.ImplementationImpl;
import org.apache.syncope.core.spring.security.utils.ImplementationLookupImpl;
import org.apache.syncope.core.spring.security.utils.PasswordGenratorEnum;
import org.apache.syncope.core.spring.security.utils.PasswordPolicyImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class DefaultPasswordGeneratorFromPoliciesTest {

    private List<PasswordPolicy> policies;
    private boolean exception;

    private PasswordGenratorEnum check;
    private int checkValue;

    @Mock
    ConfigurableApplicationContext applicationContext;

    @Before
    public void setUp() {
        applicationContext = Mockito.mock(ConfigurableApplicationContext.class);
        SecurityProperties securityProperties = new SecurityProperties();
        when(applicationContext.getBean(SecurityProperties.class)).thenReturn(securityProperties);
        ImplementationLookup implementationLookup = new ImplementationLookupImpl();
        when(applicationContext.getBean(ImplementationLookup.class)).thenReturn(implementationLookup);
        ApplicationContextProvider.setBeanFactory(new DefaultListableBeanFactory());
        ApplicationContextProvider.setApplicationContext(applicationContext);
    }

    public static PasswordPolicyImpl createPasswordPolicy(DefaultPasswordRuleConf passwordRuleConf) {
        ImplementationImpl rule = new ImplementationImpl(POJOHelper.serialize(passwordRuleConf));
        return new PasswordPolicyImpl(rule);
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {

        DefaultPasswordRuleConf validConf = new DefaultPasswordRuleConf();
        List<PasswordPolicy> validPolicies = List.of(createPasswordPolicy(validConf));

        DefaultPasswordRuleConf invalidMaxConf = new DefaultPasswordRuleConf();
        invalidMaxConf.setMaxLength(-1);
        List<PasswordPolicy> invalidMaxPolicies = List.of(createPasswordPolicy(invalidMaxConf));

        DefaultPasswordRuleConf maxConf = new DefaultPasswordRuleConf();
        maxConf.setMaxLength(1);
        List<PasswordPolicy> maxPolicies = List.of(createPasswordPolicy(maxConf));

        DefaultPasswordRuleConf zeroMaxConf = new DefaultPasswordRuleConf();
        zeroMaxConf.setMaxLength(0);
        List<PasswordPolicy> zeroMaxPolicies = List.of(createPasswordPolicy(zeroMaxConf));

        DefaultPasswordRuleConf invalidMinConf = new DefaultPasswordRuleConf();
        invalidMinConf.setMinLength(-1);
        List<PasswordPolicy> invalidMinPolicies = List.of(createPasswordPolicy(invalidMinConf));

        DefaultPasswordRuleConf minConf = new DefaultPasswordRuleConf();
        minConf.setMinLength(1);
        List<PasswordPolicy> minPolicies = List.of(createPasswordPolicy(minConf));

        DefaultPasswordRuleConf zeroMinConf = new DefaultPasswordRuleConf();
        zeroMinConf.setMinLength(0);
        List<PasswordPolicy> zeroMinPolicies = List.of(createPasswordPolicy(zeroMinConf));

        DefaultPasswordRuleConf invalidAlphaConf = new DefaultPasswordRuleConf();
        invalidAlphaConf.setAlphabetical(-1);
        List<PasswordPolicy> invalidAlphaPolicies = List.of(createPasswordPolicy(invalidAlphaConf));

        DefaultPasswordRuleConf alphaConf = new DefaultPasswordRuleConf();
        alphaConf.setAlphabetical(1);
        List<PasswordPolicy> alphaPolicies = List.of(createPasswordPolicy(alphaConf));

        DefaultPasswordRuleConf notAlphaConf = new DefaultPasswordRuleConf();
        notAlphaConf.setAlphabetical(0);
        List<PasswordPolicy> notAlphaPolicies = List.of(createPasswordPolicy(notAlphaConf));

        DefaultPasswordRuleConf invalidUpperConf = new DefaultPasswordRuleConf();
        invalidUpperConf.setUppercase(-1);
        List<PasswordPolicy> invalidUpperPolicies = List.of(createPasswordPolicy(invalidUpperConf));

        DefaultPasswordRuleConf upperConf = new DefaultPasswordRuleConf();
        upperConf.setUppercase(1);
        List<PasswordPolicy> upperPolicies = List.of(createPasswordPolicy(upperConf));

        DefaultPasswordRuleConf notUpperConf = new DefaultPasswordRuleConf();
        notUpperConf.setUppercase(0);
        List<PasswordPolicy> notUpperPolicies = List.of(createPasswordPolicy(notUpperConf));

        DefaultPasswordRuleConf invalidLowerConf = new DefaultPasswordRuleConf();
        invalidLowerConf.setLowercase(-1);
        List<PasswordPolicy> invalidLowerPolicies = List.of(createPasswordPolicy(invalidLowerConf));

        DefaultPasswordRuleConf lowerConf = new DefaultPasswordRuleConf();
        lowerConf.setLowercase(1);
        List<PasswordPolicy> lowerPolicies = List.of(createPasswordPolicy(lowerConf));

        DefaultPasswordRuleConf notLowerConf = new DefaultPasswordRuleConf();
        notLowerConf.setLowercase(0);
        List<PasswordPolicy> notLowerPolicies = List.of(createPasswordPolicy(notLowerConf));

        DefaultPasswordRuleConf invalidDigitConf = new DefaultPasswordRuleConf();
        invalidDigitConf.setDigit(-1);
        List<PasswordPolicy> invalidDigitPolicies = List.of(createPasswordPolicy(invalidDigitConf));

        DefaultPasswordRuleConf digitConf = new DefaultPasswordRuleConf();
        digitConf.setDigit(1);
        List<PasswordPolicy> digitPolicies = List.of(createPasswordPolicy(digitConf));

        DefaultPasswordRuleConf notDigitConf = new DefaultPasswordRuleConf();
        notDigitConf.setDigit(0);
        List<PasswordPolicy> notDigitPolicies = List.of(createPasswordPolicy(notDigitConf));

        DefaultPasswordRuleConf invalidSpecialConf = new DefaultPasswordRuleConf();
        invalidSpecialConf.setSpecial(-1);
        List<PasswordPolicy> invalidSpecialPolicies = List.of(createPasswordPolicy(invalidSpecialConf));

        DefaultPasswordRuleConf specialConf = new DefaultPasswordRuleConf();
        specialConf.setSpecial(1);
        List<PasswordPolicy> specialPolicies = List.of(createPasswordPolicy(specialConf));

        DefaultPasswordRuleConf notSpecialConf = new DefaultPasswordRuleConf();
        notSpecialConf.setSpecial(0);
        List<PasswordPolicy> notSpecialPolicies = List.of(createPasswordPolicy(notSpecialConf));

        DefaultPasswordRuleConf invalidSameConf = new DefaultPasswordRuleConf();
        invalidSameConf.setRepeatSame(-1);
        List<PasswordPolicy> invalidSamePolicies = List.of(createPasswordPolicy(invalidSameConf));

        DefaultPasswordRuleConf sameConf = new DefaultPasswordRuleConf();
        sameConf.setRepeatSame(1);
        List<PasswordPolicy> samePolicies = List.of(createPasswordPolicy(sameConf));

        DefaultPasswordRuleConf notSameConf = new DefaultPasswordRuleConf();
        notSameConf.setRepeatSame(0);
        List<PasswordPolicy> notSamePolicies = List.of(createPasswordPolicy(notSameConf));

        DefaultPasswordRuleConf userConf = new DefaultPasswordRuleConf();
        userConf.setUsernameAllowed(true);
        List<PasswordPolicy> userPolicies = List.of(createPasswordPolicy(userConf));

        DefaultPasswordRuleConf notUserConf = new DefaultPasswordRuleConf();
        notUserConf.setUsernameAllowed(false);
        List<PasswordPolicy> notUserPolicies = List.of(createPasswordPolicy(notUserConf));


        DefaultPasswordRuleConf firstConfig = new DefaultPasswordRuleConf();
        firstConfig.setMaxLength(5);
        firstConfig.setMinLength(4);
        ImplementationImpl firstRule = new ImplementationImpl(POJOHelper.serialize(firstConfig));
        PasswordPolicyImpl firstPolicy = new PasswordPolicyImpl(firstRule);

        DefaultPasswordRuleConf conflConfig = new DefaultPasswordRuleConf();
        conflConfig.setMaxLength(3);
        conflConfig.setMinLength(2);
        ImplementationImpl conflRule = new ImplementationImpl(POJOHelper.serialize(conflConfig));
        PasswordPolicyImpl conflPolicy = new PasswordPolicyImpl(conflRule);

        List<PasswordPolicy> conflictingPolicies = List.of(firstPolicy, conflPolicy);

        DefaultPasswordRuleConf invalidConf = new DefaultPasswordRuleConf();
        invalidConf.setMaxLength(4);
        invalidConf.setMinLength(6);
        List<PasswordPolicy> invalidPolicy = List.of(createPasswordPolicy(invalidConf));

        DefaultPasswordRuleConf conflUpperConfig = new DefaultPasswordRuleConf();
        conflUpperConfig.setUppercase(6);
        ImplementationImpl conflUpperRule = new ImplementationImpl(POJOHelper.serialize(conflUpperConfig));
        PasswordPolicyImpl conflUpperPolicy = new PasswordPolicyImpl(conflUpperRule);

        List<PasswordPolicy> conflictingUpperPolicies = List.of(firstPolicy, conflUpperPolicy);

        return Arrays.asList(new Object[][]{
                //Policies                          case                                value                   expectedException
                {null,                              null,                               0,                      true},
                {new ArrayList<PasswordPolicy>(),   null,                               0,                      false},
                {conflictingPolicies,               null,                               0,                      false}, // viene eletta l'ultima in caso di conflitto
                {validPolicies,                     null,                               0,                      false},
                {invalidPolicy,                     null,                               0,                      false}, // when confronted with invalid policies they are ignored
                {conflictingUpperPolicies,          PasswordGenratorEnum.UPPER,         4,                      false},
                //analisi unidimensionale delle policy

                {invalidMinPolicies,                null,                               0,                      false}, //5
                {minPolicies,                       null,                               0,                      true},
                {zeroMinPolicies,                   null,                               0,                      false},

                {invalidMaxPolicies,                null,                               0,                      false},
                {maxPolicies,                       null,                               0,                      true},
                {zeroMaxPolicies,                   null,                               0,                      false},

                {invalidAlphaPolicies,              null,                               0,                      false},
                {alphaPolicies,                     PasswordGenratorEnum.ALPHA,         1,                      false},
                {notAlphaPolicies,                  null,                               0,                      false},

                {invalidUpperPolicies,              null,                               0,                      false},
                {upperPolicies,                     PasswordGenratorEnum.UPPER,         1,                      false},
                {notUpperPolicies,                  null,                               0,                      false},

                {invalidLowerPolicies,              null,                               0,                      false},
                {lowerPolicies,                     PasswordGenratorEnum.LOWER,         1,                      false},
                {notLowerPolicies,                  null,                               0,                      false},

                {invalidDigitPolicies,              null,                               0,                      false},
                {digitPolicies,                     PasswordGenratorEnum.DIGIT,         1,                      false},
                {notDigitPolicies,                  null,                               0,                      false},

                {invalidSpecialPolicies,            null,                               0,                      false},
                {specialPolicies,                   null,                               0,                      true}, //errore, la lista è vuota
                {notSpecialPolicies,                null,                               0,                      false},

                {invalidSamePolicies,               null,                               0,                      false},
                {samePolicies,                      null,                               0,                      true}, //errore, la lista è vuota
                {notSamePolicies,                   null,                               0,                      false},

                {userPolicies,                      null,                               0,                      false},
                {notUserPolicies,                   null,                               0,                      false},
        });
    }

    public DefaultPasswordGeneratorFromPoliciesTest(List<PasswordPolicy> policies, PasswordGenratorEnum check, int checkValue, boolean exception) {
        this.exception = exception;
        this.policies = policies;
        this.check = check;
        this.checkValue = checkValue;
    }

    @Test
    public void testGenerate() {
        String password;
        try {
            DefaultPasswordGenerator defaultPasswordGenerator = new DefaultPasswordGenerator();
            password = defaultPasswordGenerator.generate(policies);


        } catch (Exception e) {
            e.printStackTrace();
            assert exception;
            return;
        }

        assert !exception;


        System.out.println(password);
        assert !password.isEmpty();

        //check that it follows the indicated policies
        if(check == null) {
            return;
        }

        switch (check) {
            case ALPHA -> {
                assert password.matches(".*[a-zA-Z].*");
            }
            case UPPER -> {
                assert password.matches(".*[A-Z].*");
                int count = 0;
                for (char c : password.toCharArray()) {
                    if (Character.isUpperCase(c)) {
                        count++;
                    }
                }
                assert count >= checkValue;
            }
            case LOWER -> {
                assert password.matches(".*[a-z].*");
            }
            case DIGIT -> {
                assert password.matches(".*[0-9].*");
            }
            default -> {
                assert true;
            }
        }
    }
}

