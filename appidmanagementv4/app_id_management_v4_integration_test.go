// +build integration

/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appidmanagementv4_test

import (
	"fmt"
	"os"

	"github.com/IBM/appid-go-sdk/appidmanagementv4"
	"github.com/IBM/go-sdk-core/v5/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains an integration test for the appidmanagementv4 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 */

var _ = Describe(`AppIDManagementV4 Integration Tests`, func() {

	const externalConfigFile = "../app_id_management_v4.env"

	var (
		err                    error
		appIDManagementService *appidmanagementv4.AppIDManagementV4
		serviceURL             string
		config                 map[string]string
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping tests: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(appidmanagementv4.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping tests: " + err.Error())
			}
			serviceURL = config["URL"]
			if serviceURL == "" {
				Skip("Unable to load service URL configuration property, skipping tests")
			}

			fmt.Printf("Service URL: %s\n", serviceURL)
			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {

			appIDManagementServiceOptions := &appidmanagementv4.AppIDManagementV4Options{}

			appIDManagementService, err = appidmanagementv4.NewAppIDManagementV4UsingExternalConfig(appIDManagementServiceOptions)

			Expect(err).To(BeNil())
			Expect(appIDManagementService).ToNot(BeNil())
			Expect(appIDManagementService.Service.Options.URL).To(Equal(serviceURL))
		})
	})

	Describe(`ListApplications - List applications`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListApplications(listApplicationsOptions *ListApplicationsOptions)`, func() {

			listApplicationsOptions := &appidmanagementv4.ListApplicationsOptions{
				TenantID: core.StringPtr("testString"),
			}

			applicationsList, response, err := appIDManagementService.ListApplications(listApplicationsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(applicationsList).ToNot(BeNil())

		})
	})

	Describe(`RegisterApplication - Create application`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RegisterApplication(registerApplicationOptions *RegisterApplicationOptions)`, func() {

			registerApplicationOptions := &appidmanagementv4.RegisterApplicationOptions{
				TenantID: core.StringPtr("testString"),
				Name:     core.StringPtr("testString"),
				Type:     core.StringPtr("testString"),
			}

			application, response, err := appIDManagementService.RegisterApplication(registerApplicationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(application).ToNot(BeNil())

		})
	})

	Describe(`GetApplication - Get application`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetApplication(getApplicationOptions *GetApplicationOptions)`, func() {

			getApplicationOptions := &appidmanagementv4.GetApplicationOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
			}

			application, response, err := appIDManagementService.GetApplication(getApplicationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(application).ToNot(BeNil())

		})
	})

	Describe(`UpdateApplication - Update application`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateApplication(updateApplicationOptions *UpdateApplicationOptions)`, func() {

			updateApplicationOptions := &appidmanagementv4.UpdateApplicationOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
				Name:     core.StringPtr("testString"),
			}

			application, response, err := appIDManagementService.UpdateApplication(updateApplicationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(application).ToNot(BeNil())

		})
	})

	Describe(`GetApplicationScopes - Get application scopes`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetApplicationScopes(getApplicationScopesOptions *GetApplicationScopesOptions)`, func() {

			getApplicationScopesOptions := &appidmanagementv4.GetApplicationScopesOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
			}

			getScopesForApplication, response, err := appIDManagementService.GetApplicationScopes(getApplicationScopesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getScopesForApplication).ToNot(BeNil())

		})
	})

	Describe(`PutApplicationsScopes - Add application scope`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PutApplicationsScopes(putApplicationsScopesOptions *PutApplicationsScopesOptions)`, func() {

			putApplicationsScopesOptions := &appidmanagementv4.PutApplicationsScopesOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
				Scopes:   []string{"cartoons", "horror", "animated"},
			}

			getScopesForApplication, response, err := appIDManagementService.PutApplicationsScopes(putApplicationsScopesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getScopesForApplication).ToNot(BeNil())

		})
	})

	Describe(`GetApplicationRoles - Get application roles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetApplicationRoles(getApplicationRolesOptions *GetApplicationRolesOptions)`, func() {

			getApplicationRolesOptions := &appidmanagementv4.GetApplicationRolesOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
			}

			getUserRolesResponse, response, err := appIDManagementService.GetApplicationRoles(getApplicationRolesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getUserRolesResponse).ToNot(BeNil())

		})
	})

	Describe(`PutApplicationsRoles - Add application role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PutApplicationsRoles(putApplicationsRolesOptions *PutApplicationsRolesOptions)`, func() {

			updateUserRolesParamsRolesModel := &appidmanagementv4.UpdateUserRolesParamsRoles{
				Ids: []string{"111c22c3-38ea-4de8-b5d4-338744d83b0f"},
			}

			putApplicationsRolesOptions := &appidmanagementv4.PutApplicationsRolesOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
				Roles:    updateUserRolesParamsRolesModel,
			}

			assignRoleToUser, response, err := appIDManagementService.PutApplicationsRoles(putApplicationsRolesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(assignRoleToUser).ToNot(BeNil())

		})
	})

	Describe(`ListCloudDirectoryUsers - List Cloud Directory users`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListCloudDirectoryUsers(listCloudDirectoryUsersOptions *ListCloudDirectoryUsersOptions)`, func() {

			listCloudDirectoryUsersOptions := &appidmanagementv4.ListCloudDirectoryUsersOptions{
				TenantID:   core.StringPtr("testString"),
				StartIndex: core.Int64Ptr(int64(38)),
				Count:      core.Int64Ptr(int64(0)),
				Query:      core.StringPtr("testString"),
			}

			usersList, response, err := appIDManagementService.ListCloudDirectoryUsers(listCloudDirectoryUsersOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(usersList).ToNot(BeNil())

		})
	})

	Describe(`CreateCloudDirectoryUser - Create a Cloud Directory user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateCloudDirectoryUser(createCloudDirectoryUserOptions *CreateCloudDirectoryUserOptions)`, func() {

			createNewUserEmailsItemModel := &appidmanagementv4.CreateNewUserEmailsItem{
				Value:   core.StringPtr("user@mail.com"),
				Primary: core.BoolPtr(true),
			}

			createCloudDirectoryUserOptions := &appidmanagementv4.CreateCloudDirectoryUserOptions{
				TenantID: core.StringPtr("testString"),
				Emails:   []appidmanagementv4.CreateNewUserEmailsItem{*createNewUserEmailsItemModel},
				Password: core.StringPtr("userPassword"),
				Active:   core.BoolPtr(true),
				UserName: core.StringPtr("myUserName"),
			}

			response, err := appIDManagementService.CreateCloudDirectoryUser(createCloudDirectoryUserOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))

		})
	})

	Describe(`GetCloudDirectoryUser - Get a Cloud Directory user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryUser(getCloudDirectoryUserOptions *GetCloudDirectoryUserOptions)`, func() {

			getCloudDirectoryUserOptions := &appidmanagementv4.GetCloudDirectoryUserOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
			}

			response, err := appIDManagementService.GetCloudDirectoryUser(getCloudDirectoryUserOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`UpdateCloudDirectoryUser - Update a Cloud Directory user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateCloudDirectoryUser(updateCloudDirectoryUserOptions *UpdateCloudDirectoryUserOptions)`, func() {

			createNewUserEmailsItemModel := &appidmanagementv4.CreateNewUserEmailsItem{
				Value:   core.StringPtr("user@mail.com"),
				Primary: core.BoolPtr(true),
			}

			updateCloudDirectoryUserOptions := &appidmanagementv4.UpdateCloudDirectoryUserOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
				Emails:   []appidmanagementv4.CreateNewUserEmailsItem{*createNewUserEmailsItemModel},
				Active:   core.BoolPtr(true),
				UserName: core.StringPtr("myUserName"),
				Password: core.StringPtr("userPassword"),
			}

			response, err := appIDManagementService.UpdateCloudDirectoryUser(updateCloudDirectoryUserOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`InvalidateUserSSOSessions - Invalidate all SSO sessions`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`InvalidateUserSSOSessions(invalidateUserSSOSessionsOptions *InvalidateUserSSOSessionsOptions)`, func() {

			invalidateUserSSOSessionsOptions := &appidmanagementv4.InvalidateUserSSOSessionsOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
			}

			response, err := appIDManagementService.InvalidateUserSSOSessions(invalidateUserSSOSessionsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`CloudDirectoryExport - Export Cloud Directory users`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CloudDirectoryExport(cloudDirectoryExportOptions *CloudDirectoryExportOptions)`, func() {

			cloudDirectoryExportOptions := &appidmanagementv4.CloudDirectoryExportOptions{
				EncryptionSecret: core.StringPtr("testString"),
				TenantID:         core.StringPtr("testString"),
				StartIndex:       core.Int64Ptr(int64(38)),
				Count:            core.Int64Ptr(int64(0)),
			}

			exportUser, response, err := appIDManagementService.CloudDirectoryExport(cloudDirectoryExportOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(exportUser).ToNot(BeNil())

		})
	})

	Describe(`CloudDirectoryImport - Import Cloud Directory users`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CloudDirectoryImport(cloudDirectoryImportOptions *CloudDirectoryImportOptions)`, func() {

			exportUserUsersItemProfileModel := &appidmanagementv4.ExportUserUsersItemProfile{
				Attributes: map[string]interface{}{"anyKey": "anyValue"},
			}

			exportUserUsersItemModel := &appidmanagementv4.ExportUserUsersItem{
				ScimUser:        map[string]interface{}{"anyKey": "anyValue"},
				PasswordHash:    core.StringPtr("testString"),
				PasswordHashAlg: core.StringPtr("testString"),
				Profile:         exportUserUsersItemProfileModel,
				Roles:           []string{"testString"},
			}

			cloudDirectoryImportOptions := &appidmanagementv4.CloudDirectoryImportOptions{
				EncryptionSecret: core.StringPtr("testString"),
				TenantID:         core.StringPtr("testString"),
				Users:            []appidmanagementv4.ExportUserUsersItem{*exportUserUsersItemModel},
			}

			importResponse, response, err := appIDManagementService.CloudDirectoryImport(cloudDirectoryImportOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(importResponse).ToNot(BeNil())

		})
	})

	Describe(`CloudDirectoryGetUserinfo - Get Cloud Directory SCIM and Attributes`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CloudDirectoryGetUserinfo(cloudDirectoryGetUserinfoOptions *CloudDirectoryGetUserinfoOptions)`, func() {

			cloudDirectoryGetUserinfoOptions := &appidmanagementv4.CloudDirectoryGetUserinfoOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
			}

			getUserAndProfile, response, err := appIDManagementService.CloudDirectoryGetUserinfo(cloudDirectoryGetUserinfoOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getUserAndProfile).ToNot(BeNil())

		})
	})

	Describe(`StartSignUp - Sign up`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`StartSignUp(startSignUpOptions *StartSignUpOptions)`, func() {

			createNewUserEmailsItemModel := &appidmanagementv4.CreateNewUserEmailsItem{
				Value:   core.StringPtr("user@mail.com"),
				Primary: core.BoolPtr(true),
			}

			startSignUpOptions := &appidmanagementv4.StartSignUpOptions{
				TenantID:            core.StringPtr("testString"),
				ShouldCreateProfile: core.BoolPtr(true),
				Emails:              []appidmanagementv4.CreateNewUserEmailsItem{*createNewUserEmailsItemModel},
				Password:            core.StringPtr("userPassword"),
				Active:              core.BoolPtr(true),
				UserName:            core.StringPtr("myUserName"),
				Language:            core.StringPtr("testString"),
			}

			response, err := appIDManagementService.StartSignUp(startSignUpOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))

		})
	})

	Describe(`UserVerificationResult - Get signup confirmation result`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UserVerificationResult(userVerificationResultOptions *UserVerificationResultOptions)`, func() {

			userVerificationResultOptions := &appidmanagementv4.UserVerificationResultOptions{
				TenantID: core.StringPtr("testString"),
				Context:  core.StringPtr("testString"),
			}

			confirmationResultOk, response, err := appIDManagementService.UserVerificationResult(userVerificationResultOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(confirmationResultOk).ToNot(BeNil())

		})
	})

	Describe(`StartForgotPassword - Forgot password`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`StartForgotPassword(startForgotPasswordOptions *StartForgotPasswordOptions)`, func() {

			startForgotPasswordOptions := &appidmanagementv4.StartForgotPasswordOptions{
				TenantID: core.StringPtr("testString"),
				User:     core.StringPtr("testString"),
				Language: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.StartForgotPassword(startForgotPasswordOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`ForgotPasswordResult - Forgot password confirmation result`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ForgotPasswordResult(forgotPasswordResultOptions *ForgotPasswordResultOptions)`, func() {

			forgotPasswordResultOptions := &appidmanagementv4.ForgotPasswordResultOptions{
				TenantID: core.StringPtr("testString"),
				Context:  core.StringPtr("testString"),
			}

			confirmationResultOk, response, err := appIDManagementService.ForgotPasswordResult(forgotPasswordResultOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(confirmationResultOk).ToNot(BeNil())

		})
	})

	Describe(`ChangePassword - Change password`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ChangePassword(changePasswordOptions *ChangePasswordOptions)`, func() {

			changePasswordOptions := &appidmanagementv4.ChangePasswordOptions{
				TenantID:         core.StringPtr("testString"),
				NewPassword:      core.StringPtr("testString"),
				UUID:             core.StringPtr("testString"),
				ChangedIPAddress: core.StringPtr("testString"),
				Language:         core.StringPtr("testString"),
			}

			response, err := appIDManagementService.ChangePassword(changePasswordOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`ResendNotification - Resend user notifications`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ResendNotification(resendNotificationOptions *ResendNotificationOptions)`, func() {

			resendNotificationOptions := &appidmanagementv4.ResendNotificationOptions{
				TenantID:     core.StringPtr("testString"),
				TemplateName: core.StringPtr("USER_VERIFICATION"),
				UUID:         core.StringPtr("testString"),
				Language:     core.StringPtr("testString"),
			}

			resendNotificationResponse, response, err := appIDManagementService.ResendNotification(resendNotificationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(202))
			Expect(resendNotificationResponse).ToNot(BeNil())

		})
	})

	Describe(`GetTokensConfig - Get tokens configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetTokensConfig(getTokensConfigOptions *GetTokensConfigOptions)`, func() {

			getTokensConfigOptions := &appidmanagementv4.GetTokensConfigOptions{
				TenantID: core.StringPtr("testString"),
			}

			tokensConfigResponse, response, err := appIDManagementService.GetTokensConfig(getTokensConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(tokensConfigResponse).ToNot(BeNil())

		})
	})

	Describe(`PutTokensConfig - Update tokens configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PutTokensConfig(putTokensConfigOptions *PutTokensConfigOptions)`, func() {

			tokenClaimMappingModel := &appidmanagementv4.TokenClaimMapping{
				Source:           core.StringPtr("saml"),
				SourceClaim:      core.StringPtr("testString"),
				DestinationClaim: core.StringPtr("testString"),
			}

			accessTokenConfigParamsModel := &appidmanagementv4.AccessTokenConfigParams{
				ExpiresIn: core.Int64Ptr(int64(3600)),
			}

			tokenConfigParamsModel := &appidmanagementv4.TokenConfigParams{
				ExpiresIn: core.Int64Ptr(int64(2592000)),
				Enabled:   core.BoolPtr(true),
			}

			putTokensConfigOptions := &appidmanagementv4.PutTokensConfigOptions{
				TenantID:          core.StringPtr("testString"),
				IDTokenClaims:     []appidmanagementv4.TokenClaimMapping{*tokenClaimMappingModel},
				AccessTokenClaims: []appidmanagementv4.TokenClaimMapping{*tokenClaimMappingModel},
				Access:            accessTokenConfigParamsModel,
				Refresh:           tokenConfigParamsModel,
				AnonymousAccess:   tokenConfigParamsModel,
			}

			tokensConfigResponse, response, err := appIDManagementService.PutTokensConfig(putTokensConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(tokensConfigResponse).ToNot(BeNil())

		})
	})

	Describe(`GetRedirectUris - Get redirect URIs`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRedirectUris(getRedirectUrisOptions *GetRedirectUrisOptions)`, func() {

			getRedirectUrisOptions := &appidmanagementv4.GetRedirectUrisOptions{
				TenantID: core.StringPtr("testString"),
			}

			redirectURIResponse, response, err := appIDManagementService.GetRedirectUris(getRedirectUrisOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(redirectURIResponse).ToNot(BeNil())

		})
	})

	Describe(`UpdateRedirectUris - Update redirect URIs`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateRedirectUris(updateRedirectUrisOptions *UpdateRedirectUrisOptions)`, func() {

			redirectURIConfigModel := &appidmanagementv4.RedirectURIConfig{
				RedirectUris:              []string{"http://localhost:3000/oauth-callback"},
				TrustCloudIAMRedirectUris: core.BoolPtr(true),
			}
			redirectURIConfigModel.SetProperty("foo", core.StringPtr("testString"))

			updateRedirectUrisOptions := &appidmanagementv4.UpdateRedirectUrisOptions{
				TenantID:          core.StringPtr("testString"),
				RedirectUrisArray: redirectURIConfigModel,
			}

			response, err := appIDManagementService.UpdateRedirectUris(updateRedirectUrisOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetUserProfilesConfig - Get user profiles configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetUserProfilesConfig(getUserProfilesConfigOptions *GetUserProfilesConfigOptions)`, func() {

			getUserProfilesConfigOptions := &appidmanagementv4.GetUserProfilesConfigOptions{
				TenantID: core.StringPtr("testString"),
			}

			getUserProfilesConfigResponse, response, err := appIDManagementService.GetUserProfilesConfig(getUserProfilesConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getUserProfilesConfigResponse).ToNot(BeNil())

		})
	})

	Describe(`UpdateUserProfilesConfig - Update user profiles configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateUserProfilesConfig(updateUserProfilesConfigOptions *UpdateUserProfilesConfigOptions)`, func() {

			updateUserProfilesConfigOptions := &appidmanagementv4.UpdateUserProfilesConfigOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
			}

			response, err := appIDManagementService.UpdateUserProfilesConfig(updateUserProfilesConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetThemeText - Get widget texts`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetThemeText(getThemeTextOptions *GetThemeTextOptions)`, func() {

			getThemeTextOptions := &appidmanagementv4.GetThemeTextOptions{
				TenantID: core.StringPtr("testString"),
			}

			getThemeTextResponse, response, err := appIDManagementService.GetThemeText(getThemeTextOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getThemeTextResponse).ToNot(BeNil())

		})
	})

	Describe(`PostThemeText - Update widget texts`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostThemeText(postThemeTextOptions *PostThemeTextOptions)`, func() {

			postThemeTextOptions := &appidmanagementv4.PostThemeTextOptions{
				TenantID: core.StringPtr("testString"),
				TabTitle: core.StringPtr("Login"),
				Footnote: core.StringPtr("Powered by App ID"),
			}

			response, err := appIDManagementService.PostThemeText(postThemeTextOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetThemeColor - Get widget colors`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetThemeColor(getThemeColorOptions *GetThemeColorOptions)`, func() {

			getThemeColorOptions := &appidmanagementv4.GetThemeColorOptions{
				TenantID: core.StringPtr("testString"),
			}

			getThemeColorResponse, response, err := appIDManagementService.GetThemeColor(getThemeColorOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getThemeColorResponse).ToNot(BeNil())

		})
	})

	Describe(`PostThemeColor - Update widget colors`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostThemeColor(postThemeColorOptions *PostThemeColorOptions)`, func() {

			postThemeColorOptions := &appidmanagementv4.PostThemeColorOptions{
				TenantID:    core.StringPtr("testString"),
				HeaderColor: core.StringPtr("#EEF2F5"),
			}

			response, err := appIDManagementService.PostThemeColor(postThemeColorOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetMedia - Get widget logo`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetMedia(getMediaOptions *GetMediaOptions)`, func() {

			getMediaOptions := &appidmanagementv4.GetMediaOptions{
				TenantID: core.StringPtr("testString"),
			}

			getMediaResponse, response, err := appIDManagementService.GetMedia(getMediaOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getMediaResponse).ToNot(BeNil())

		})
	})

	Describe(`PostMedia - Update widget logo`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostMedia(postMediaOptions *PostMediaOptions)`, func() {

			postMediaOptions := &appidmanagementv4.PostMediaOptions{
				TenantID:        core.StringPtr("testString"),
				MediaType:       core.StringPtr("logo"),
				File:            CreateMockReader("This is a mock file."),
				FileContentType: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.PostMedia(postMediaOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetSAMLMetadata - Get the SAML metadata`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSAMLMetadata(getSAMLMetadataOptions *GetSAMLMetadataOptions)`, func() {

			getSAMLMetadataOptions := &appidmanagementv4.GetSAMLMetadataOptions{
				TenantID: core.StringPtr("testString"),
			}

			result, response, err := appIDManagementService.GetSAMLMetadata(getSAMLMetadataOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(result).ToNot(BeNil())

		})
	})

	Describe(`GetTemplate - Get an email template`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetTemplate(getTemplateOptions *GetTemplateOptions)`, func() {

			getTemplateOptions := &appidmanagementv4.GetTemplateOptions{
				TenantID:     core.StringPtr("testString"),
				TemplateName: core.StringPtr("USER_VERIFICATION"),
				Language:     core.StringPtr("testString"),
			}

			getTemplate, response, err := appIDManagementService.GetTemplate(getTemplateOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getTemplate).ToNot(BeNil())

		})
	})

	Describe(`UpdateTemplate - Update an email template`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateTemplate(updateTemplateOptions *UpdateTemplateOptions)`, func() {

			updateTemplateOptions := &appidmanagementv4.UpdateTemplateOptions{
				TenantID:              core.StringPtr("testString"),
				TemplateName:          core.StringPtr("USER_VERIFICATION"),
				Language:              core.StringPtr("testString"),
				Subject:               core.StringPtr("testString"),
				HTMLBody:              core.StringPtr("testString"),
				Base64EncodedHTMLBody: core.StringPtr("testString"),
				PlainTextBody:         core.StringPtr("testString"),
			}

			getTemplate, response, err := appIDManagementService.UpdateTemplate(updateTemplateOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getTemplate).ToNot(BeNil())

		})
	})

	Describe(`GetLocalization - Get languages`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetLocalization(getLocalizationOptions *GetLocalizationOptions)`, func() {

			getLocalizationOptions := &appidmanagementv4.GetLocalizationOptions{
				TenantID: core.StringPtr("testString"),
			}

			getLanguages, response, err := appIDManagementService.GetLocalization(getLocalizationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getLanguages).ToNot(BeNil())

		})
	})

	Describe(`UpdateLocalization - Update languages`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateLocalization(updateLocalizationOptions *UpdateLocalizationOptions)`, func() {

			updateLocalizationOptions := &appidmanagementv4.UpdateLocalizationOptions{
				TenantID:  core.StringPtr("testString"),
				Languages: []string{"testString"},
			}

			response, err := appIDManagementService.UpdateLocalization(updateLocalizationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetCloudDirectorySenderDetails - Get sender details`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectorySenderDetails(getCloudDirectorySenderDetailsOptions *GetCloudDirectorySenderDetailsOptions)`, func() {

			getCloudDirectorySenderDetailsOptions := &appidmanagementv4.GetCloudDirectorySenderDetailsOptions{
				TenantID: core.StringPtr("testString"),
			}

			cloudDirectorySenderDetails, response, err := appIDManagementService.GetCloudDirectorySenderDetails(getCloudDirectorySenderDetailsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(cloudDirectorySenderDetails).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectorySenderDetails - Update the sender details`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectorySenderDetails(setCloudDirectorySenderDetailsOptions *SetCloudDirectorySenderDetailsOptions)`, func() {

			cloudDirectorySenderDetailsSenderDetailsFromModel := &appidmanagementv4.CloudDirectorySenderDetailsSenderDetailsFrom{
				Name:  core.StringPtr("testString"),
				Email: core.StringPtr("testString"),
			}

			cloudDirectorySenderDetailsSenderDetailsReplyToModel := &appidmanagementv4.CloudDirectorySenderDetailsSenderDetailsReplyTo{
				Name:  core.StringPtr("testString"),
				Email: core.StringPtr("testString"),
			}

			cloudDirectorySenderDetailsSenderDetailsModel := &appidmanagementv4.CloudDirectorySenderDetailsSenderDetails{
				From:              cloudDirectorySenderDetailsSenderDetailsFromModel,
				ReplyTo:           cloudDirectorySenderDetailsSenderDetailsReplyToModel,
				LinkExpirationSec: core.Int64Ptr(int64(900)),
			}

			setCloudDirectorySenderDetailsOptions := &appidmanagementv4.SetCloudDirectorySenderDetailsOptions{
				TenantID:      core.StringPtr("testString"),
				SenderDetails: cloudDirectorySenderDetailsSenderDetailsModel,
			}

			response, err := appIDManagementService.SetCloudDirectorySenderDetails(setCloudDirectorySenderDetailsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`GetCloudDirectoryActionURL - Get action url`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryActionURL(getCloudDirectoryActionURLOptions *GetCloudDirectoryActionURLOptions)`, func() {

			getCloudDirectoryActionURLOptions := &appidmanagementv4.GetCloudDirectoryActionURLOptions{
				TenantID: core.StringPtr("testString"),
				Action:   core.StringPtr("on_user_verified"),
			}

			actionURLResponse, response, err := appIDManagementService.GetCloudDirectoryActionURL(getCloudDirectoryActionURLOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(actionURLResponse).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectoryAction - Update action url`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectoryAction(setCloudDirectoryActionOptions *SetCloudDirectoryActionOptions)`, func() {

			setCloudDirectoryActionOptions := &appidmanagementv4.SetCloudDirectoryActionOptions{
				TenantID:  core.StringPtr("testString"),
				Action:    core.StringPtr("on_user_verified"),
				ActionURL: core.StringPtr("testString"),
			}

			actionURLResponse, response, err := appIDManagementService.SetCloudDirectoryAction(setCloudDirectoryActionOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(actionURLResponse).ToNot(BeNil())

		})
	})

	Describe(`GetCloudDirectoryPasswordRegex - Get password regex`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryPasswordRegex(getCloudDirectoryPasswordRegexOptions *GetCloudDirectoryPasswordRegexOptions)`, func() {

			getCloudDirectoryPasswordRegexOptions := &appidmanagementv4.GetCloudDirectoryPasswordRegexOptions{
				TenantID: core.StringPtr("testString"),
			}

			passwordRegexConfigParamsGet, response, err := appIDManagementService.GetCloudDirectoryPasswordRegex(getCloudDirectoryPasswordRegexOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(passwordRegexConfigParamsGet).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectoryPasswordRegex - Update password regex`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectoryPasswordRegex(setCloudDirectoryPasswordRegexOptions *SetCloudDirectoryPasswordRegexOptions)`, func() {

			setCloudDirectoryPasswordRegexOptions := &appidmanagementv4.SetCloudDirectoryPasswordRegexOptions{
				TenantID:           core.StringPtr("testString"),
				Regex:              core.StringPtr("testString"),
				Base64EncodedRegex: core.StringPtr("testString"),
				ErrorMessage:       core.StringPtr("testString"),
			}

			passwordRegexConfigParamsGet, response, err := appIDManagementService.SetCloudDirectoryPasswordRegex(setCloudDirectoryPasswordRegexOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(passwordRegexConfigParamsGet).ToNot(BeNil())

		})
	})

	Describe(`GetCloudDirectoryEmailDispatcher - Get email dispatcher configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryEmailDispatcher(getCloudDirectoryEmailDispatcherOptions *GetCloudDirectoryEmailDispatcherOptions)`, func() {

			getCloudDirectoryEmailDispatcherOptions := &appidmanagementv4.GetCloudDirectoryEmailDispatcherOptions{
				TenantID: core.StringPtr("testString"),
			}

			emailDispatcherParams, response, err := appIDManagementService.GetCloudDirectoryEmailDispatcher(getCloudDirectoryEmailDispatcherOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(emailDispatcherParams).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectoryEmailDispatcher - Update email dispatcher configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectoryEmailDispatcher(setCloudDirectoryEmailDispatcherOptions *SetCloudDirectoryEmailDispatcherOptions)`, func() {

			emailDispatcherParamsSendgridModel := &appidmanagementv4.EmailDispatcherParamsSendgrid{
				APIKey: core.StringPtr("testString"),
			}

			emailDispatcherParamsCustomAuthorizationModel := &appidmanagementv4.EmailDispatcherParamsCustomAuthorization{
				Type:     core.StringPtr("value"),
				Value:    core.StringPtr("testString"),
				Username: core.StringPtr("testString"),
				Password: core.StringPtr("testString"),
			}

			emailDispatcherParamsCustomModel := &appidmanagementv4.EmailDispatcherParamsCustom{
				URL:           core.StringPtr("testString"),
				Authorization: emailDispatcherParamsCustomAuthorizationModel,
			}

			setCloudDirectoryEmailDispatcherOptions := &appidmanagementv4.SetCloudDirectoryEmailDispatcherOptions{
				TenantID: core.StringPtr("testString"),
				Provider: core.StringPtr("sendgrid"),
				Sendgrid: emailDispatcherParamsSendgridModel,
				Custom:   emailDispatcherParamsCustomModel,
			}

			emailDispatcherParams, response, err := appIDManagementService.SetCloudDirectoryEmailDispatcher(setCloudDirectoryEmailDispatcherOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(emailDispatcherParams).ToNot(BeNil())

		})
	})

	Describe(`EmailSettingTest - Test the email provider configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`EmailSettingTest(emailSettingTestOptions *EmailSettingTestOptions)`, func() {

			emailSettingsTestParamsEmailSettingsSendgridModel := &appidmanagementv4.EmailSettingsTestParamsEmailSettingsSendgrid{
				APIKey: core.StringPtr("testString"),
			}

			emailSettingsTestParamsEmailSettingsCustomAuthorizationModel := &appidmanagementv4.EmailSettingsTestParamsEmailSettingsCustomAuthorization{
				Type:     core.StringPtr("value"),
				Value:    core.StringPtr("testString"),
				Username: core.StringPtr("testString"),
				Password: core.StringPtr("testString"),
			}

			emailSettingsTestParamsEmailSettingsCustomModel := &appidmanagementv4.EmailSettingsTestParamsEmailSettingsCustom{
				URL:           core.StringPtr("testString"),
				Authorization: emailSettingsTestParamsEmailSettingsCustomAuthorizationModel,
			}

			emailSettingsTestParamsEmailSettingsModel := &appidmanagementv4.EmailSettingsTestParamsEmailSettings{
				Provider: core.StringPtr("sendgrid"),
				Sendgrid: emailSettingsTestParamsEmailSettingsSendgridModel,
				Custom:   emailSettingsTestParamsEmailSettingsCustomModel,
			}

			emailSettingsTestParamsSenderDetailsFromModel := &appidmanagementv4.EmailSettingsTestParamsSenderDetailsFrom{
				Email: core.StringPtr("testString"),
				Name:  core.StringPtr("testString"),
			}

			emailSettingsTestParamsSenderDetailsReplyToModel := &appidmanagementv4.EmailSettingsTestParamsSenderDetailsReplyTo{
				Email: core.StringPtr("testString"),
				Name:  core.StringPtr("testString"),
			}

			emailSettingsTestParamsSenderDetailsModel := &appidmanagementv4.EmailSettingsTestParamsSenderDetails{
				From:    emailSettingsTestParamsSenderDetailsFromModel,
				ReplyTo: emailSettingsTestParamsSenderDetailsReplyToModel,
			}

			emailSettingTestOptions := &appidmanagementv4.EmailSettingTestOptions{
				TenantID:      core.StringPtr("testString"),
				EmailTo:       core.StringPtr("testString"),
				EmailSettings: emailSettingsTestParamsEmailSettingsModel,
				SenderDetails: emailSettingsTestParamsSenderDetailsModel,
			}

			respEmailSettingsTest, response, err := appIDManagementService.EmailSettingTest(emailSettingTestOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(respEmailSettingsTest).ToNot(BeNil())

		})
	})

	Describe(`PostEmailDispatcherTest - Test the email dispatcher configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostEmailDispatcherTest(postEmailDispatcherTestOptions *PostEmailDispatcherTestOptions)`, func() {

			postEmailDispatcherTestOptions := &appidmanagementv4.PostEmailDispatcherTestOptions{
				TenantID: core.StringPtr("testString"),
				Email:    core.StringPtr("testString"),
			}

			respCustomEmailDisParams, response, err := appIDManagementService.PostEmailDispatcherTest(postEmailDispatcherTestOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(respCustomEmailDisParams).ToNot(BeNil())

		})
	})

	Describe(`PostSMSDispatcherTest - Test the MFA SMS dispatcher configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostSMSDispatcherTest(postSMSDispatcherTestOptions *PostSMSDispatcherTestOptions)`, func() {

			postSMSDispatcherTestOptions := &appidmanagementv4.PostSMSDispatcherTestOptions{
				TenantID:    core.StringPtr("testString"),
				PhoneNumber: core.StringPtr("+1-999-999-9999"),
			}

			respSMSDisParams, response, err := appIDManagementService.PostSMSDispatcherTest(postSMSDispatcherTestOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(respSMSDisParams).ToNot(BeNil())

		})
	})

	Describe(`GetCloudDirectoryAdvancedPasswordManagement - Get APM configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryAdvancedPasswordManagement(getCloudDirectoryAdvancedPasswordManagementOptions *GetCloudDirectoryAdvancedPasswordManagementOptions)`, func() {

			getCloudDirectoryAdvancedPasswordManagementOptions := &appidmanagementv4.GetCloudDirectoryAdvancedPasswordManagementOptions{
				TenantID: core.StringPtr("testString"),
			}

			apmSchema, response, err := appIDManagementService.GetCloudDirectoryAdvancedPasswordManagement(getCloudDirectoryAdvancedPasswordManagementOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(apmSchema).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectoryAdvancedPasswordManagement - Update APM configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectoryAdvancedPasswordManagement(setCloudDirectoryAdvancedPasswordManagementOptions *SetCloudDirectoryAdvancedPasswordManagementOptions)`, func() {

			apmSchemaAdvancedPasswordManagementPasswordReuseConfigModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementPasswordReuseConfig{
				MaxPasswordReuse: core.Int64Ptr(int64(1)),
			}

			apmSchemaAdvancedPasswordManagementPasswordReuseModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementPasswordReuse{
				Enabled: core.BoolPtr(true),
				Config:  apmSchemaAdvancedPasswordManagementPasswordReuseConfigModel,
			}

			apmSchemaAdvancedPasswordManagementPreventPasswordWithUsernameModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementPreventPasswordWithUsername{
				Enabled: core.BoolPtr(true),
			}

			apmSchemaAdvancedPasswordManagementPasswordExpirationConfigModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementPasswordExpirationConfig{
				DaysToExpire: core.Int64Ptr(int64(1)),
			}

			apmSchemaAdvancedPasswordManagementPasswordExpirationModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementPasswordExpiration{
				Enabled: core.BoolPtr(true),
				Config:  apmSchemaAdvancedPasswordManagementPasswordExpirationConfigModel,
			}

			apmSchemaAdvancedPasswordManagementLockOutPolicyConfigModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementLockOutPolicyConfig{
				LockOutTimeSec: core.Int64Ptr(int64(60)),
				NumOfAttempts:  core.Int64Ptr(int64(1)),
			}

			apmSchemaAdvancedPasswordManagementLockOutPolicyModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementLockOutPolicy{
				Enabled: core.BoolPtr(true),
				Config:  apmSchemaAdvancedPasswordManagementLockOutPolicyConfigModel,
			}

			apmSchemaAdvancedPasswordManagementMinPasswordChangeIntervalConfigModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementMinPasswordChangeIntervalConfig{
				MinHoursToChangePassword: core.Int64Ptr(int64(0)),
			}

			apmSchemaAdvancedPasswordManagementMinPasswordChangeIntervalModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagementMinPasswordChangeInterval{
				Enabled: core.BoolPtr(true),
				Config:  apmSchemaAdvancedPasswordManagementMinPasswordChangeIntervalConfigModel,
			}

			apmSchemaAdvancedPasswordManagementModel := &appidmanagementv4.ApmSchemaAdvancedPasswordManagement{
				Enabled:                     core.BoolPtr(true),
				PasswordReuse:               apmSchemaAdvancedPasswordManagementPasswordReuseModel,
				PreventPasswordWithUsername: apmSchemaAdvancedPasswordManagementPreventPasswordWithUsernameModel,
				PasswordExpiration:          apmSchemaAdvancedPasswordManagementPasswordExpirationModel,
				LockOutPolicy:               apmSchemaAdvancedPasswordManagementLockOutPolicyModel,
				MinPasswordChangeInterval:   apmSchemaAdvancedPasswordManagementMinPasswordChangeIntervalModel,
			}

			setCloudDirectoryAdvancedPasswordManagementOptions := &appidmanagementv4.SetCloudDirectoryAdvancedPasswordManagementOptions{
				TenantID:                   core.StringPtr("testString"),
				AdvancedPasswordManagement: apmSchemaAdvancedPasswordManagementModel,
			}

			apmSchema, response, err := appIDManagementService.SetCloudDirectoryAdvancedPasswordManagement(setCloudDirectoryAdvancedPasswordManagementOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(apmSchema).ToNot(BeNil())

		})
	})

	Describe(`GetAuditStatus - Get tenant audit status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetAuditStatus(getAuditStatusOptions *GetAuditStatusOptions)`, func() {

			getAuditStatusOptions := &appidmanagementv4.GetAuditStatusOptions{
				TenantID: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.GetAuditStatus(getAuditStatusOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`SetAuditStatus - Update tenant audit status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetAuditStatus(setAuditStatusOptions *SetAuditStatusOptions)`, func() {

			setAuditStatusOptions := &appidmanagementv4.SetAuditStatusOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
			}

			response, err := appIDManagementService.SetAuditStatus(setAuditStatusOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`ListChannels - List channels`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListChannels(listChannelsOptions *ListChannelsOptions)`, func() {

			listChannelsOptions := &appidmanagementv4.ListChannelsOptions{
				TenantID: core.StringPtr("testString"),
			}

			mfaChannelsList, response, err := appIDManagementService.ListChannels(listChannelsOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(mfaChannelsList).ToNot(BeNil())

		})
	})

	Describe(`GetChannel - Get channel`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetChannel(getChannelOptions *GetChannelOptions)`, func() {

			getChannelOptions := &appidmanagementv4.GetChannelOptions{
				TenantID: core.StringPtr("testString"),
				Channel:  core.StringPtr("email"),
			}

			getSMSChannel, response, err := appIDManagementService.GetChannel(getChannelOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getSMSChannel).ToNot(BeNil())

		})
	})

	Describe(`UpdateChannel - Update channel`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateChannel(updateChannelOptions *UpdateChannelOptions)`, func() {

			updateChannelOptions := &appidmanagementv4.UpdateChannelOptions{
				TenantID: core.StringPtr("testString"),
				Channel:  core.StringPtr("email"),
				IsActive: core.BoolPtr(true),
				Config:   map[string]interface{}{"anyKey": "anyValue"},
			}

			getSMSChannel, response, err := appIDManagementService.UpdateChannel(updateChannelOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getSMSChannel).ToNot(BeNil())

		})
	})

	Describe(`GetExtensionConfig - Get an extension configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetExtensionConfig(getExtensionConfigOptions *GetExtensionConfigOptions)`, func() {

			getExtensionConfigOptions := &appidmanagementv4.GetExtensionConfigOptions{
				TenantID: core.StringPtr("testString"),
				Name:     core.StringPtr("premfa"),
			}

			updateExtensionConfig, response, err := appIDManagementService.GetExtensionConfig(getExtensionConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(updateExtensionConfig).ToNot(BeNil())

		})
	})

	Describe(`UpdateExtensionConfig - Update an extension configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateExtensionConfig(updateExtensionConfigOptions *UpdateExtensionConfigOptions)`, func() {

			updateExtensionConfigConfigModel := &appidmanagementv4.UpdateExtensionConfigConfig{
				URL:        core.StringPtr("testString"),
				HeadersVar: map[string]interface{}{"anyKey": "anyValue"},
			}

			updateExtensionConfigOptions := &appidmanagementv4.UpdateExtensionConfigOptions{
				TenantID: core.StringPtr("testString"),
				Name:     core.StringPtr("premfa"),
				IsActive: core.BoolPtr(true),
				Config:   updateExtensionConfigConfigModel,
			}

			updateExtensionConfig, response, err := appIDManagementService.UpdateExtensionConfig(updateExtensionConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(updateExtensionConfig).ToNot(BeNil())

		})
	})

	Describe(`UpdateExtensionActive - Enable or disable an extension`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateExtensionActive(updateExtensionActiveOptions *UpdateExtensionActiveOptions)`, func() {

			updateExtensionActiveOptions := &appidmanagementv4.UpdateExtensionActiveOptions{
				TenantID: core.StringPtr("testString"),
				Name:     core.StringPtr("premfa"),
				IsActive: core.BoolPtr(true),
				Config:   map[string]interface{}{"anyKey": "anyValue"},
			}

			extensionActive, response, err := appIDManagementService.UpdateExtensionActive(updateExtensionActiveOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(extensionActive).ToNot(BeNil())

		})
	})

	Describe(`PostExtensionsTest - Test the extension configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostExtensionsTest(postExtensionsTestOptions *PostExtensionsTestOptions)`, func() {

			postExtensionsTestOptions := &appidmanagementv4.PostExtensionsTestOptions{
				TenantID: core.StringPtr("testString"),
				Name:     core.StringPtr("premfa"),
			}

			extensionTest, response, err := appIDManagementService.PostExtensionsTest(postExtensionsTestOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(extensionTest).ToNot(BeNil())

		})
	})

	Describe(`GetMFAConfig - Get MFA configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetMFAConfig(getMFAConfigOptions *GetMFAConfigOptions)`, func() {

			getMFAConfigOptions := &appidmanagementv4.GetMFAConfigOptions{
				TenantID: core.StringPtr("testString"),
			}

			getMFAConfiguration, response, err := appIDManagementService.GetMFAConfig(getMFAConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getMFAConfiguration).ToNot(BeNil())

		})
	})

	Describe(`UpdateMFAConfig - Update MFA configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateMFAConfig(updateMFAConfigOptions *UpdateMFAConfigOptions)`, func() {

			updateMFAConfigOptions := &appidmanagementv4.UpdateMFAConfigOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
				Config:   map[string]interface{}{"anyKey": "anyValue"},
			}

			getMFAConfiguration, response, err := appIDManagementService.UpdateMFAConfig(updateMFAConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getMFAConfiguration).ToNot(BeNil())

		})
	})

	Describe(`GetSSOConfig - Get SSO configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSSOConfig(getSSOConfigOptions *GetSSOConfigOptions)`, func() {

			getSSOConfigOptions := &appidmanagementv4.GetSSOConfigOptions{
				TenantID: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.GetSSOConfig(getSSOConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`UpdateSSOConfig - Update SSO configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateSSOConfig(updateSSOConfigOptions *UpdateSSOConfigOptions)`, func() {

			updateSSOConfigOptions := &appidmanagementv4.UpdateSSOConfigOptions{
				TenantID:                 core.StringPtr("testString"),
				IsActive:                 core.BoolPtr(true),
				InactivityTimeoutSeconds: core.Int64Ptr(int64(86400)),
				LogoutRedirectUris:       []string{"http://localhost:3000/logout-callback"},
			}

			response, err := appIDManagementService.UpdateSSOConfig(updateSSOConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))

		})
	})

	Describe(`GetRateLimitConfig - Get the rate limit configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRateLimitConfig(getRateLimitConfigOptions *GetRateLimitConfigOptions)`, func() {

			getRateLimitConfigOptions := &appidmanagementv4.GetRateLimitConfigOptions{
				TenantID: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.GetRateLimitConfig(getRateLimitConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`UpdateRateLimitConfig - Update the rate limit configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateRateLimitConfig(updateRateLimitConfigOptions *UpdateRateLimitConfigOptions)`, func() {

			updateRateLimitConfigOptions := &appidmanagementv4.UpdateRateLimitConfigOptions{
				TenantID:             core.StringPtr("testString"),
				SignUpLimitPerMinute: core.Int64Ptr(int64(50)),
				SignInLimitPerMinute: core.Int64Ptr(int64(60)),
			}

			response, err := appIDManagementService.UpdateRateLimitConfig(updateRateLimitConfigOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))

		})
	})

	Describe(`GetFacebookIDP - Get Facebook IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetFacebookIDP(getFacebookIDPOptions *GetFacebookIDPOptions)`, func() {

			getFacebookIDPOptions := &appidmanagementv4.GetFacebookIDPOptions{
				TenantID: core.StringPtr("testString"),
			}

			facebookConfigParams, response, err := appIDManagementService.GetFacebookIDP(getFacebookIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(facebookConfigParams).ToNot(BeNil())

		})
	})

	Describe(`SetFacebookIDP - Update Facebook IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetFacebookIDP(setFacebookIDPOptions *SetFacebookIDPOptions)`, func() {

			facebookGoogleConfigParamsConfigModel := &appidmanagementv4.FacebookGoogleConfigParamsConfig{
				IDPID:  core.StringPtr("appID"),
				Secret: core.StringPtr("appsecret"),
			}

			facebookGoogleConfigParamsModel := &appidmanagementv4.FacebookGoogleConfigParams{
				IsActive: core.BoolPtr(true),
				Config:   facebookGoogleConfigParamsConfigModel,
			}
			facebookGoogleConfigParamsModel.SetProperty("foo", core.StringPtr("testString"))

			setFacebookIDPOptions := &appidmanagementv4.SetFacebookIDPOptions{
				TenantID: core.StringPtr("testString"),
				IDP:      facebookGoogleConfigParamsModel,
			}

			facebookConfigParamsPut, response, err := appIDManagementService.SetFacebookIDP(setFacebookIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(facebookConfigParamsPut).ToNot(BeNil())

		})
	})

	Describe(`GetGoogleIDP - Get Google IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetGoogleIDP(getGoogleIDPOptions *GetGoogleIDPOptions)`, func() {

			getGoogleIDPOptions := &appidmanagementv4.GetGoogleIDPOptions{
				TenantID: core.StringPtr("testString"),
			}

			googleConfigParams, response, err := appIDManagementService.GetGoogleIDP(getGoogleIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(googleConfigParams).ToNot(BeNil())

		})
	})

	Describe(`SetGoogleIDP - Update Google IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetGoogleIDP(setGoogleIDPOptions *SetGoogleIDPOptions)`, func() {

			facebookGoogleConfigParamsConfigModel := &appidmanagementv4.FacebookGoogleConfigParamsConfig{
				IDPID:  core.StringPtr("appID"),
				Secret: core.StringPtr("appsecret"),
			}

			facebookGoogleConfigParamsModel := &appidmanagementv4.FacebookGoogleConfigParams{
				IsActive: core.BoolPtr(true),
				Config:   facebookGoogleConfigParamsConfigModel,
			}
			facebookGoogleConfigParamsModel.SetProperty("foo", core.StringPtr("testString"))

			setGoogleIDPOptions := &appidmanagementv4.SetGoogleIDPOptions{
				TenantID: core.StringPtr("testString"),
				IDP:      facebookGoogleConfigParamsModel,
			}

			googleConfigParamsPut, response, err := appIDManagementService.SetGoogleIDP(setGoogleIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(googleConfigParamsPut).ToNot(BeNil())

		})
	})

	Describe(`GetCustomIDP - Returns the Custom identity configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCustomIDP(getCustomIDPOptions *GetCustomIDPOptions)`, func() {

			getCustomIDPOptions := &appidmanagementv4.GetCustomIDPOptions{
				TenantID: core.StringPtr("testString"),
			}

			customIDPConfigParams, response, err := appIDManagementService.GetCustomIDP(getCustomIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(customIDPConfigParams).ToNot(BeNil())

		})
	})

	Describe(`SetCustomIDP - Update or change the configuration of the Custom identity`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCustomIDP(setCustomIDPOptions *SetCustomIDPOptions)`, func() {

			customIDPConfigParamsConfigModel := &appidmanagementv4.CustomIDPConfigParamsConfig{
				PublicKey: core.StringPtr("testString"),
			}

			setCustomIDPOptions := &appidmanagementv4.SetCustomIDPOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
				Config:   customIDPConfigParamsConfigModel,
			}

			customIDPConfigParams, response, err := appIDManagementService.SetCustomIDP(setCustomIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(customIDPConfigParams).ToNot(BeNil())

		})
	})

	Describe(`GetCloudDirectoryIDP - Get Cloud Directory IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCloudDirectoryIDP(getCloudDirectoryIDPOptions *GetCloudDirectoryIDPOptions)`, func() {

			getCloudDirectoryIDPOptions := &appidmanagementv4.GetCloudDirectoryIDPOptions{
				TenantID: core.StringPtr("testString"),
			}

			cloudDirectoryResponse, response, err := appIDManagementService.GetCloudDirectoryIDP(getCloudDirectoryIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(cloudDirectoryResponse).ToNot(BeNil())

		})
	})

	Describe(`SetCloudDirectoryIDP - Update Cloud Directory IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetCloudDirectoryIDP(setCloudDirectoryIDPOptions *SetCloudDirectoryIDPOptions)`, func() {

			cloudDirectoryConfigParamsInteractionsIdentityConfirmationModel := &appidmanagementv4.CloudDirectoryConfigParamsInteractionsIdentityConfirmation{
				AccessMode: core.StringPtr("FULL"),
				Methods:    []string{"email"},
			}

			cloudDirectoryConfigParamsInteractionsModel := &appidmanagementv4.CloudDirectoryConfigParamsInteractions{
				IdentityConfirmation:            cloudDirectoryConfigParamsInteractionsIdentityConfirmationModel,
				WelcomeEnabled:                  core.BoolPtr(false),
				ResetPasswordEnabled:            core.BoolPtr(false),
				ResetPasswordNotificationEnable: core.BoolPtr(true),
			}

			cloudDirectoryConfigParamsModel := &appidmanagementv4.CloudDirectoryConfigParams{
				SelfServiceEnabled: core.BoolPtr(true),
				SignupEnabled:      core.BoolPtr(true),
				Interactions:       cloudDirectoryConfigParamsInteractionsModel,
				IdentityField:      core.StringPtr("email"),
			}

			setCloudDirectoryIDPOptions := &appidmanagementv4.SetCloudDirectoryIDPOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
				Config:   cloudDirectoryConfigParamsModel,
			}

			cloudDirectoryResponse, response, err := appIDManagementService.SetCloudDirectoryIDP(setCloudDirectoryIDPOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(cloudDirectoryResponse).ToNot(BeNil())

		})
	})

	Describe(`GetSAMLIDP - Get SAML IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetSAMLIDP(getSAMLIDPOptions *GetSAMLIDPOptions)`, func() {

			getSamlidpOptions := &appidmanagementv4.GetSAMLIDPOptions{
				TenantID: core.StringPtr("testString"),
			}

			samlResponse, response, err := appIDManagementService.GetSAMLIDP(getSamlidpOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(samlResponse).ToNot(BeNil())

		})
	})

	Describe(`SetSAMLIDP - Update SAML IDP configuration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetSAMLIDP(setSAMLIDPOptions *SetSAMLIDPOptions)`, func() {

			samlConfigParamsAuthnContextModel := &appidmanagementv4.SAMLConfigParamsAuthnContext{
				Class:      []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"},
				Comparison: core.StringPtr("exact"),
			}

			samlConfigParamsModel := &appidmanagementv4.SAMLConfigParams{
				EntityID:        core.StringPtr("testString"),
				SignInURL:       core.StringPtr("testString"),
				Certificates:    []string{"testString"},
				DisplayName:     core.StringPtr("testString"),
				AuthnContext:    samlConfigParamsAuthnContextModel,
				SignRequest:     core.BoolPtr(false),
				EncryptResponse: core.BoolPtr(false),
				IncludeScoping:  core.BoolPtr(false),
			}
			samlConfigParamsModel.SetProperty("foo", core.StringPtr("testString"))

			setSamlidpOptions := &appidmanagementv4.SetSAMLIDPOptions{
				TenantID: core.StringPtr("testString"),
				IsActive: core.BoolPtr(true),
				Config:   samlConfigParamsModel,
			}

			samlResponseWithValidationData, response, err := appIDManagementService.SetSAMLIDP(setSamlidpOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(samlResponseWithValidationData).ToNot(BeNil())

		})
	})

	Describe(`ListRoles - List all roles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListRoles(listRolesOptions *ListRolesOptions)`, func() {

			listRolesOptions := &appidmanagementv4.ListRolesOptions{
				TenantID: core.StringPtr("testString"),
			}

			rolesList, response, err := appIDManagementService.ListRoles(listRolesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(rolesList).ToNot(BeNil())

		})
	})

	Describe(`CreateRole - Create a role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateRole(createRoleOptions *CreateRoleOptions)`, func() {

			createRoleParamsAccessItemModel := &appidmanagementv4.CreateRoleParamsAccessItem{
				ApplicationID: core.StringPtr("de33d272-f8a7-4406-8fe8-ab28fd457be5"),
				Scopes:        []string{"cartoons"},
			}

			createRoleOptions := &appidmanagementv4.CreateRoleOptions{
				TenantID:    core.StringPtr("testString"),
				Name:        core.StringPtr("child"),
				Access:      []appidmanagementv4.CreateRoleParamsAccessItem{*createRoleParamsAccessItemModel},
				Description: core.StringPtr("Limits the available movie options to those that might be more appropriate for younger viewers."),
			}

			createRolesResponse, response, err := appIDManagementService.CreateRole(createRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(createRolesResponse).ToNot(BeNil())

		})
	})

	Describe(`GetRole - View a specific role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRole(getRoleOptions *GetRoleOptions)`, func() {

			getRoleOptions := &appidmanagementv4.GetRoleOptions{
				TenantID: core.StringPtr("testString"),
				RoleID:   core.StringPtr("testString"),
			}

			getRoleResponse, response, err := appIDManagementService.GetRole(getRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getRoleResponse).ToNot(BeNil())

		})
	})

	Describe(`UpdateRole - Update a role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateRole(updateRoleOptions *UpdateRoleOptions)`, func() {

			updateRoleParamsAccessItemModel := &appidmanagementv4.UpdateRoleParamsAccessItem{
				ApplicationID: core.StringPtr("de33d272-f8a7-4406-8fe8-ab28fd457be5"),
				Scopes:        []string{"cartoons", "animated"},
			}

			updateRoleOptions := &appidmanagementv4.UpdateRoleOptions{
				TenantID:    core.StringPtr("testString"),
				RoleID:      core.StringPtr("testString"),
				Name:        core.StringPtr("child"),
				Access:      []appidmanagementv4.UpdateRoleParamsAccessItem{*updateRoleParamsAccessItemModel},
				Description: core.StringPtr("Limits the available movie options to those that might be more appropriate for younger viewers."),
			}

			updateRolesResponse, response, err := appIDManagementService.UpdateRole(updateRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(updateRolesResponse).ToNot(BeNil())

		})
	})

	Describe(`UsersSearchUserProfile - Search users`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersSearchUserProfile(usersSearchUserProfileOptions *UsersSearchUserProfileOptions)`, func() {

			usersSearchUserProfileOptions := &appidmanagementv4.UsersSearchUserProfileOptions{
				TenantID:   core.StringPtr("testString"),
				DataScope:  core.StringPtr("index"),
				Email:      core.StringPtr("testString"),
				ID:         core.StringPtr("testString"),
				StartIndex: core.Int64Ptr(int64(38)),
				Count:      core.Int64Ptr(int64(0)),
			}

			userSearchResponse, response, err := appIDManagementService.UsersSearchUserProfile(usersSearchUserProfileOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(userSearchResponse).ToNot(BeNil())

		})
	})

	Describe(`UsersNominateUser - Pre-register a user profile`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersNominateUser(usersNominateUserOptions *UsersNominateUserOptions)`, func() {

			usersNominateUserParamsProfileModel := &appidmanagementv4.UsersNominateUserParamsProfile{
				Attributes: make(map[string]interface{}),
			}

			usersNominateUserOptions := &appidmanagementv4.UsersNominateUserOptions{
				TenantID:    core.StringPtr("testString"),
				IDP:         core.StringPtr("saml"),
				IDPIdentity: core.StringPtr("appid@ibm.com"),
				Profile:     usersNominateUserParamsProfileModel,
			}

			response, err := appIDManagementService.UsersNominateUser(usersNominateUserOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))

		})
	})

	Describe(`UserProfilesExport - Export user profiles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UserProfilesExport(userProfilesExportOptions *UserProfilesExportOptions)`, func() {

			userProfilesExportOptions := &appidmanagementv4.UserProfilesExportOptions{
				TenantID:   core.StringPtr("testString"),
				StartIndex: core.Int64Ptr(int64(38)),
				Count:      core.Int64Ptr(int64(0)),
			}

			exportUserProfile, response, err := appIDManagementService.UserProfilesExport(userProfilesExportOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(exportUserProfile).ToNot(BeNil())

		})
	})

	Describe(`UserProfilesImport - Import user profiles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UserProfilesImport(userProfilesImportOptions *UserProfilesImportOptions)`, func() {

			exportUserProfileUsersItemIdentitiesItemModel := &appidmanagementv4.ExportUserProfileUsersItemIdentitiesItem{
				Provider:    core.StringPtr("testString"),
				ID:          core.StringPtr("testString"),
				IDPUserInfo: map[string]interface{}{"anyKey": "anyValue"},
			}
			exportUserProfileUsersItemIdentitiesItemModel.SetProperty("foo", core.StringPtr("testString"))

			exportUserProfileUsersItemModel := &appidmanagementv4.ExportUserProfileUsersItem{
				ID:                core.StringPtr("testString"),
				Identities:        []appidmanagementv4.ExportUserProfileUsersItemIdentitiesItem{*exportUserProfileUsersItemIdentitiesItemModel},
				Attributes:        map[string]interface{}{"anyKey": "anyValue"},
				Name:              core.StringPtr("testString"),
				Email:             core.StringPtr("testString"),
				Picture:           core.StringPtr("testString"),
				Gender:            core.StringPtr("testString"),
				Locale:            core.StringPtr("testString"),
				PreferredUsername: core.StringPtr("testString"),
				IDP:               core.StringPtr("testString"),
				HashedIDPID:       core.StringPtr("testString"),
				HashedEmail:       core.StringPtr("testString"),
				Roles:             []string{"testString"},
			}

			userProfilesImportOptions := &appidmanagementv4.UserProfilesImportOptions{
				TenantID: core.StringPtr("testString"),
				Users:    []appidmanagementv4.ExportUserProfileUsersItem{*exportUserProfileUsersItemModel},
			}

			importProfilesResponse, response, err := appIDManagementService.UserProfilesImport(userProfilesImportOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(importProfilesResponse).ToNot(BeNil())

		})
	})

	Describe(`UsersRevokeRefreshToken - Revoke refresh token`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersRevokeRefreshToken(usersRevokeRefreshTokenOptions *UsersRevokeRefreshTokenOptions)`, func() {

			usersRevokeRefreshTokenOptions := &appidmanagementv4.UsersRevokeRefreshTokenOptions{
				TenantID: core.StringPtr("testString"),
				ID:       core.StringPtr("testString"),
			}

			response, err := appIDManagementService.UsersRevokeRefreshToken(usersRevokeRefreshTokenOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`UsersGetUserProfile - Get user profile`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersGetUserProfile(usersGetUserProfileOptions *UsersGetUserProfileOptions)`, func() {

			usersGetUserProfileOptions := &appidmanagementv4.UsersGetUserProfileOptions{
				TenantID: core.StringPtr("testString"),
				ID:       core.StringPtr("testString"),
			}

			response, err := appIDManagementService.UsersGetUserProfile(usersGetUserProfileOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`UsersSetUserProfile - Update user profile`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersSetUserProfile(usersSetUserProfileOptions *UsersSetUserProfileOptions)`, func() {

			usersSetUserProfileOptions := &appidmanagementv4.UsersSetUserProfileOptions{
				TenantID:   core.StringPtr("testString"),
				ID:         core.StringPtr("testString"),
				Attributes: make(map[string]interface{}),
			}

			response, err := appIDManagementService.UsersSetUserProfile(usersSetUserProfileOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))

		})
	})

	Describe(`GetUserRoles - Get a user's roles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetUserRoles(getUserRolesOptions *GetUserRolesOptions)`, func() {

			getUserRolesOptions := &appidmanagementv4.GetUserRolesOptions{
				TenantID: core.StringPtr("testString"),
				ID:       core.StringPtr("testString"),
			}

			getUserRolesResponse, response, err := appIDManagementService.GetUserRoles(getUserRolesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getUserRolesResponse).ToNot(BeNil())

		})
	})

	Describe(`UpdateUserRoles - Update a user's roles`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateUserRoles(updateUserRolesOptions *UpdateUserRolesOptions)`, func() {

			updateUserRolesParamsRolesModel := &appidmanagementv4.UpdateUserRolesParamsRoles{
				Ids: []string{"111c22c3-38ea-4de8-b5d4-338744d83b0f"},
			}

			updateUserRolesOptions := &appidmanagementv4.UpdateUserRolesOptions{
				TenantID: core.StringPtr("testString"),
				ID:       core.StringPtr("testString"),
				Roles:    updateUserRolesParamsRolesModel,
			}

			assignRoleToUser, response, err := appIDManagementService.UpdateUserRoles(updateUserRolesOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(assignRoleToUser).ToNot(BeNil())

		})
	})

	Describe(`UsersDeleteUserProfile - Delete user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UsersDeleteUserProfile(usersDeleteUserProfileOptions *UsersDeleteUserProfileOptions)`, func() {

			usersDeleteUserProfileOptions := &appidmanagementv4.UsersDeleteUserProfileOptions{
				TenantID: core.StringPtr("testString"),
				ID:       core.StringPtr("testString"),
			}

			response, err := appIDManagementService.UsersDeleteUserProfile(usersDeleteUserProfileOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteTemplate - Delete an email template`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteTemplate(deleteTemplateOptions *DeleteTemplateOptions)`, func() {

			deleteTemplateOptions := &appidmanagementv4.DeleteTemplateOptions{
				TenantID:     core.StringPtr("testString"),
				TemplateName: core.StringPtr("USER_VERIFICATION"),
				Language:     core.StringPtr("testString"),
			}

			response, err := appIDManagementService.DeleteTemplate(deleteTemplateOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteRole - Delete a role`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteRole(deleteRoleOptions *DeleteRoleOptions)`, func() {

			deleteRoleOptions := &appidmanagementv4.DeleteRoleOptions{
				TenantID: core.StringPtr("testString"),
				RoleID:   core.StringPtr("testString"),
			}

			response, err := appIDManagementService.DeleteRole(deleteRoleOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(202))

		})
	})

	Describe(`DeleteCloudDirectoryUser - Delete a Cloud Directory user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteCloudDirectoryUser(deleteCloudDirectoryUserOptions *DeleteCloudDirectoryUserOptions)`, func() {

			deleteCloudDirectoryUserOptions := &appidmanagementv4.DeleteCloudDirectoryUserOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
			}

			response, err := appIDManagementService.DeleteCloudDirectoryUser(deleteCloudDirectoryUserOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteApplication - Delete application`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteApplication(deleteApplicationOptions *DeleteApplicationOptions)`, func() {

			deleteApplicationOptions := &appidmanagementv4.DeleteApplicationOptions{
				TenantID: core.StringPtr("testString"),
				ClientID: core.StringPtr("testString"),
			}

			response, err := appIDManagementService.DeleteApplication(deleteApplicationOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`DeleteActionURL - Delete action url`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteActionURL(deleteActionURLOptions *DeleteActionURLOptions)`, func() {

			deleteActionURLOptions := &appidmanagementv4.DeleteActionURLOptions{
				TenantID: core.StringPtr("testString"),
				Action:   core.StringPtr("on_user_verified"),
			}

			response, err := appIDManagementService.DeleteActionURL(deleteActionURLOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})

	Describe(`CloudDirectoryRemove - Delete Cloud Directory User and Profile`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CloudDirectoryRemove(cloudDirectoryRemoveOptions *CloudDirectoryRemoveOptions)`, func() {

			cloudDirectoryRemoveOptions := &appidmanagementv4.CloudDirectoryRemoveOptions{
				TenantID: core.StringPtr("testString"),
				UserID:   core.StringPtr("testString"),
			}

			response, err := appIDManagementService.CloudDirectoryRemove(cloudDirectoryRemoveOptions)

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))

		})
	})
})

//
// Utility functions are declared in the unit test file
//
