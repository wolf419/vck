package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.aroundEach
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

val AgentPQCJwtTest by testSuite {


    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var challenge: String
    lateinit var singularPresentationDefinition: PresentationExchangePresentation

    testConfig = TestConfig.aroundEach {
        issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithoutCert(key = EphemeralKey{ ml {} }.getOrThrow()),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )

        holderKeyMaterial = EphemeralKeyWithoutCert(key = EphemeralKey { ml {} }.getOrThrow())
        holder = HolderAgent(holderKeyMaterial)

        verifier = VerifierAgent(identifier = "https://verifier.example.com/")

        challenge = uuid4().toString()

        singularPresentationDefinition = PresentationExchangePresentation(
            CredentialPresentationRequest.PresentationExchangeRequest(
                PresentationDefinition(DifInputDescriptor(id = uuid4().toString()))))

        it()
    }

    "test" {
        // create a credential to be issued
//        val credentialToBeIssued1: CredentialToBeIssued = DummyCredentialDataProvider.getCredential(
//            holderKeyMaterial.publicKey,
//            ConstantIndex.AtomicAttribute2023,
//            PLAIN_JWT).getOrThrow()

        val issuanceDate = Clock.System.now()
        val expirationDate = issuanceDate + 60.seconds
        val subjectId = holderKeyMaterial.publicKey.didEncoded

        // Create the credential that we want to issue
        // Needs to be decided in WP 4.1
        val credentialToBeIssued = CredentialToBeIssued.VcJwt(
            subject = AtomicAttribute2023(subjectId, CLAIM_GIVEN_NAME, "Jakob",),
            expiration = expirationDate,
            scheme = ConstantIndex.AtomicAttribute2023,
            subjectPublicKey = holderKeyMaterial.publicKey,
            userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
        )

        // Issue the credential to be issued
        val credential = issuer.issueCredential(credentialToBeIssued).getOrThrow() as Issuer.IssuedCredential.VcJwt
        println(credential.signedVcJws.serialize())

        // Store the credential
        holder.storeCredential(credential.toStoreCredentialInput())

        val presentationParameters = holder.createPresentation(
            PresentationRequestParameters(challenge, "example.com"),
            singularPresentationDefinition).getOrThrow()
            .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        // Create a verifiable presentation
        val vp = presentationParameters.presentationResults.first()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()

        // Verify a verifiable presentation
        verifier.verifyPresentationVcJwt(vp.jwsSigned, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
    }
}
