package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

val AgentPQCJwtTest by testSuite {
    withFixtureGenerator(suspend  {
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithoutCert(key = EphemeralKey{ ml {} }.getOrThrow()),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )

        val holderKeyMaterial = EphemeralKeyWithoutCert(key = EphemeralKey { ml {} }.getOrThrow())
        val holder = HolderAgent(holderKeyMaterial)

        val verifier = VerifierAgent(identifier = "https://verifier.example.com/")

        val challenge = uuid4().toString()

        val singularPresentationDefinition = PresentationExchangePresentation(
            CredentialPresentationRequest.PresentationExchangeRequest(
                PresentationDefinition(DifInputDescriptor(id = uuid4().toString()))))

        object {
            val issuer = issuer
            val holder = holder
            val verifier = verifier
            val challenge = challenge
            val singularPresentationDefinition = singularPresentationDefinition
            val holderKeyMaterial = holderKeyMaterial

        }
    }) - {

    "test" {
        // create a credential to be issued
//        val credentialToBeIssued1: CredentialToBeIssued = DummyCredentialDataProvider.getCredential(
//            holderKeyMaterial.publicKey,
//            ConstantIndex.AtomicAttribute2023,
//            PLAIN_JWT).getOrThrow()

        val issuanceDate = Clock.System.now()
        val expirationDate = issuanceDate + 60.seconds
        val subjectId = it.holderKeyMaterial.publicKey.didEncoded

        // Create the credential that we want to issue
        // Needs to be decided in WP 4.1
        val credentialToBeIssued = CredentialToBeIssued.VcJwt(
            subject = AtomicAttribute2023(subjectId, CLAIM_GIVEN_NAME, "Jakob",),
            expiration = expirationDate,
            scheme = ConstantIndex.AtomicAttribute2023,
            subjectPublicKey = it.holderKeyMaterial.publicKey,
            userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
        )

        // Issue the credential to be issued
        val credential = it.issuer.issueCredential(credentialToBeIssued).getOrThrow() as Issuer.IssuedCredential.VcJwt
        println(credential.signedVcJws.serialize())

        // Store the credential
        it.holder.storeCredential(credential.toStoreCredentialInput())

        val presentationParameters = it.holder.createPresentation(
            PresentationRequestParameters(it.challenge, "example.com"),
            it.singularPresentationDefinition).getOrThrow()
            .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        // Create a verifiable presentation
        val vp = presentationParameters.presentationResults.first()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()

        // Verify a verifiable presentation
        it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }
    }
}
