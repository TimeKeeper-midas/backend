import {readFile} from 'node:fs/promises';
import {env} from 'node:process';
import {ApolloServer} from '@apollo/server';
// eslint-disable-next-line import/extensions
import {startStandaloneServer} from '@apollo/server/standalone';
import {PrismaClient} from '@prisma/client';
import type {User} from '@prisma/client';
import {
	generateRegistrationOptions,
	verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {GraphQLError} from 'graphql';
import type {GraphQLFieldResolver} from 'graphql';

type Context = {
	user: User | undefined;
};

const rpName = 'TimeKeeper';
const rpId = 'tk-hackathon.azurewebsites.net';
const origin = `https://${rpId}`;

const resolvers: Record<string, Record<string, GraphQLFieldResolver<unknown, Context, unknown>>> = {
	Query: {
		books: () => [],
	},
	Mutation: {
		async addCompany(parent, args: {email: string; displayName: string;}, context) {},
		async addUser(parent, args: {email: string; displayName: string;}, context) {
			if (requireAdmin(context.user)) {
				if ((await prisma.user.findUnique({where: {
					email: args.email
				}})) !== null) {
					throw new GraphQLError('이미 등록된 이메일입니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				await prisma.user.create({
					data: {
						company: {
							connect: {
								id: context.user.companyId
							},
						},
						email: args.email,
						displayName: args.displayName,
					}
				});
			}
		},
		async startRegistrationChallenge(parent, args, context) {
			if (requireLogin(context.user)){
				const options = generateRegistrationOptions({
				rpName,
				rpID: rpId,
				userID: context.user.id,
				userName: context.user.email,
				attestationType: 'none',
			});

			await prisma.user.update({
				where: {
					id: context.user.id,
				},
				data: {
					registrationChallenge: options.challenge,
				}
			});

			return options;
		}
		},
		async finishRegistrationChallenge(parent, args: {attestation: Record<string, any>}, context) {
			if (requireLogin(context.user)){
				if (context.user.registrationChallenge === null) {
					throw new GraphQLError('시작된 챌린지가 없습니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				const verification = await verifyRegistrationResponse({
					credential: args.attestation,
					expectedChallenge: context.user.registrationChallenge,
					expectedOrigin: origin,
					expectedRPID: rpId,
				});
			}
		},
		registerTransaction(parent, args, context) {},
		beacon(parent, args, context) {},
	},
};

const prisma = new PrismaClient();

await prisma.$connect();

const server = new ApolloServer<Context>({
	typeDefs: await readFile('../schema.graphql', 'utf8'),
	resolvers,
});

const {url} = await startStandaloneServer(server, {
	listen: {
		port: Number.parseInt(env.PORT ?? '4000', 10),
	},
	async context({req}) {
		const token = req.headers.authorization;

		let user: User | undefined;

		if (typeof token !== 'undefined'){
			user = (await prisma.user.findUnique({
				where: {id: ''},
			})) ?? undefined;
		}

		return {
			user,
		};
	},
});

console.log(`🚀  Server ready at: ${url}`);

function requireLogin(user: User | undefined): user is User {
	if (typeof user === 'undefined') {
		throw new GraphQLError('로그인해주세요.', {
			extensions: {
				http: {
					status: 401,
				},
			},
		});
	}

	return true;
}

function requireAdmin(user: User | undefined): user is User {
	if (requireLogin(user) && user.isAdmin === false) {
		throw new GraphQLError('관리자만 접근할 수 있습니다. ^^', {
			extensions: {
				http: {
					status: 403,
				},
			},
		});
	}

	return true;
}
