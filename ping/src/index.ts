import { APIGatewayEvent, APIGatewayProxyResultV2, Handler } from 'aws-lambda';
import { APIInteraction, APIInteractionResponse, InteractionResponseType, InteractionType } from 'discord.js';
import { ExpectedError } from './ExpectedError.js';
import nacl from 'tweetnacl';

type Responder = (interaction: APIInteraction) => Promise<APIInteractionResponse>;

export const handler: Handler<APIGatewayEvent, APIGatewayProxyResultV2> = async (event) => {
	try {
		const publicKey = getEnv('APPLICATION_PUBLIC_KEY');
	
		return isVerifiedRequest(event, publicKey)
			? {
				statusCode: 200,
				body: await main(event),
			} : {
				statusCode: 401,
				body: 'Invalid request signature.',
			};
	} catch (e) {
		if (e instanceof ExpectedError) {
			return {
				statusCode: 400,
				body: e.message,
			};
		}

		return {
			statusCode: 500,
			body: 'Unexpected error.',
		};
	}
}

function getEnv(name: string): string {
	const value = process.env[name];

	if (!value) {
		throw new TypeError(`The environment ${name} is not defined.`);
	}

	return value;
}

function isVerifiedRequest(event: APIGatewayEvent, publicKey: string): boolean {
	const signature = event.headers['X-Signature-Ed25519'] ?? '';
	const timestamp = event.headers['X-Signature-Timestamp'] ?? '';
	const body = event.body;

	return nacl.sign.detached.verify(
		Buffer.from(timestamp + body),
		Buffer.from(signature, 'hex'),
		Buffer.from(publicKey, 'hex'),
	);
}

async function main(event: APIGatewayEvent): Promise<string> {
	const applicationId = getEnv('APPLICATION_ID');

	const interaction = JSON.parse(event.body ?? '');
	if (!isInteraction(interaction, applicationId)) {
		throw new ExpectedError('The body is not a Discord Interaction structure.');
	}

	const responder = routing(interaction);
	const response = await responder(interaction);

	return JSON.stringify(response);
}

function isInteraction(interaction: any, applicationId: string): interaction is APIInteraction {
	return interaction['application_id'] === applicationId;
}

function routing(interaction: APIInteraction): Responder {
	if (interaction.type === InteractionType.Ping) {
		return async () => ({ type: InteractionResponseType.Pong });
	}

	throw new ExpectedError('The type of interaction that was unexpected.');
}
