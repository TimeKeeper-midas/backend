import {Buffer} from 'node:buffer';
import {readFile} from 'node:fs/promises';
import {env} from 'node:process';
import {ApolloServer} from '@apollo/server';
// eslint-disable-next-line n/file-extension-in-import
import {startStandaloneServer} from '@apollo/server/standalone';
import {PrismaClient} from '@prisma/client';
import type {User} from '@prisma/client';
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
	VerifiedAuthenticationResponse,
	VerifiedRegistrationResponse,
} from '@simplewebauthn/server';
import type {RegistrationCredentialJSON} from '@simplewebauthn/typescript-types';
import {GraphQLError, GraphQLScalarType, Kind} from 'graphql';
import type {GraphQLFieldResolver} from 'graphql';
import type {JWTVerifyResult} from 'jose';
import {jwtVerify, SignJWT} from 'jose';

type Context = {
	user: User | undefined;
};

const rpName = 'TimeKeeper';
const rpId = 'tk-hackathon.azurewebsites.net';
const origin = 'https://timekeeper-midas.github.io';

const resolvers: Record<
	string,
	Record<string, string | GraphQLFieldResolver<unknown, Context>>
> = {
	Date: new GraphQLScalarType({
		name: 'Date',
		description: 'Date custom scalar type',
		// eslint-disable-next-line @typescript-eslint/ban-types
		serialize(value: unknown): number | null {
			return value instanceof Date
				? value.getTime()
				: typeof value === 'number'
				? value
				: null;
		},
		// eslint-disable-next-line @typescript-eslint/ban-types
		parseValue(value: unknown): Date | null {
			return typeof value === 'number' ? new Date(value) : null;
		},
		parseLiteral(ast) {
			return ast.kind === Kind.INT
				? new Date(Number.parseInt(ast.value, 10))
				: null;
		},
	}),
	Query: {
		async company(parent, args, context) {
			if (requireLogin(context.user)) {
				const company = await prisma.company.findUnique({
					where: {
						id: context.user.companyId,
					},
				});

				if (company === null) {
					throw new GraphQLError('존재하지 않는 회사입니다.', {
						extensions: {
							http: {
								status: 409,
							},
						},
					});
				}

				return company;
			}
		},
		async users(parent, args, context) {
			if (requireAdmin(context.user)) {
				const company = await prisma.company.findUnique({
					where: {
						id: context.user.companyId,
					},
					select: {
						users: true,
					},
				});

				if (company === null) {
					throw new GraphQLError('존재하지 않는 회사입니다.', {
						extensions: {
							http: {
								status: 409,
							},
						},
					});
				}

				return company.users;
			}
		},
		user(parent, args, context) {
			if (requireLogin(context.user)) {
				return context.user;
			}
		},
		async transactions(
			parent,
			args: {startDate?: Date; endDate?: Date; userIds?: string[]},
			context,
		) {
			if (typeof args.userIds === 'undefined' && requireLogin(context.user)) {
				return prisma.transaction.findMany({
					where: {
						userId: context.user.id,
						createdAt: {
							gte: args.startDate,
							lte: args.endDate,
						},
					},
					include: {
						user: true,
					},
				});
			}

			if (requireAdmin(context.user)) {
				const company = await prisma.company.findUnique({
					where: {
						id: context.user.companyId,
					},
					select: {
						users: {
							where: {
								id: {
									in: args.userIds,
								},
							},
							select: {
								transactions: {
									where: {
										createdAt: {
											gte: args.startDate,
											lte: args.endDate,
										},
									},
									include: {
										user: true,
									},
								},
							},
						},
					},
				});

				if (company === null) {
					throw new GraphQLError('존재하지 않는 회사입니다.', {
						extensions: {
							http: {
								status: 409,
							},
						},
					});
				}

				return company.users.map(({transactions}) => transactions);
			}
		},
	},
	Mutation: {
		async addCompany(
			parent,
			args: {
				adminEmail: string;
				adminDisplayName: string;
				displayName: string;
				primaryEmail: string;
			},
			context,
		) {
			if (
				(await prisma.user.findUnique({
					where: {
						email: args.adminEmail,
					},
					select: {},
				})) !== null
			) {
				throw new GraphQLError('다른 회사에 등록된 관리 사원 이메일입니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (
				(await prisma.company.findUnique({
					where: {
						primaryEmail: args.primaryEmail,
					},
					select: {},
				})) !== null
			) {
				throw new GraphQLError('다른 회사에 등록된 기업 대표 이메일입니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			const {company} = await prisma.user.create({
				data: {
					company: {
						create: {
							displayName: args.displayName,
							primaryEmail: args.primaryEmail,
						},
					},
					email: args.adminEmail,
					displayName: args.adminDisplayName,
					isAdmin: true,
				},
				select: {
					company: true,
				},
			});

			return company;
		},
		async upsertUser(
			parent,
			args: {email: string; displayName: string; isAdmin?: boolean},
			context,
		) {
			if (requireAdmin(context.user)) {
				const user = await prisma.user.findUnique({
					where: {
						email: args.email,
					},
					select: {
						companyId: true,
					},
				});

				if (user !== null && user.companyId !== context.user.companyId) {
					throw new GraphQLError('다른 회사에 등록된 이메일입니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				return prisma.user.upsert({
					where: {
						email: args.email,
					},
					create: {
						company: {
							connect: {
								id: context.user.companyId,
							},
						},
						email: args.email,
						displayName: args.displayName,
						isAdmin: args.isAdmin,
					},
					update: {
						email: args.email,
						displayName: args.displayName,
						isAdmin: args.isAdmin,
					},
				});
			}
		},
		async deleteUser(parent, args: {id: string}, context) {
			if (requireAdmin(context.user)) {
				const user = await prisma.user.findUnique({
					where: {
						id: args.id,
					},
					select: {
						id: true,
					},
				});

				if (user === null) {
					throw new GraphQLError('존재하지 않는 사원입니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				return prisma.user.delete({
					where: {
						id: user.id,
					},
				});
			}
		},
		async startRegistrationChallenge(parent, args: {email: string}, context) {
			const user = await prisma.user.findUnique({
				where: {email: args.email},
				select: {
					id: true,
					email: true,
					authenticator: {
						select: {},
					},
				},
			});

			if (user === null) {
				throw new GraphQLError('존재하지 않는 사용자입니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (user.authenticator !== null) {
				throw new GraphQLError('이미 챌린지가 완료되었습니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			const options = generateRegistrationOptions({
				rpName,
				rpID: rpId,
				userID: user.id,
				userName: user.email,
				attestationType: 'none',
			});

			await prisma.user.update({
				where: {
					id: user.id,
				},
				data: {
					registrationChallenge: options.challenge,
				},
			});

			return JSON.stringify(options);
		},
		async finishRegistrationChallenge(
			parent,
			args: {email: string; attestation: string},
			context,
		) {
			const user = await prisma.user.findUnique({
				where: {email: args.email},
				select: {
					id: true,
					registrationChallenge: true,
				},
			});

			if (user === null) {
				throw new GraphQLError('존재하지 않는 사용자입니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (user.registrationChallenge === null) {
				throw new GraphQLError('시작된 챌린지가 없습니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			let verification: VerifiedRegistrationResponse;
			try {
				verification = await verifyRegistrationResponse({
					credential: JSON.parse(args.attestation) as RegistrationCredentialJSON,
					expectedChallenge: user.registrationChallenge,
					expectedOrigin: origin,
					expectedRPID: rpId,
				});
			} catch (error: unknown) {
				throw new GraphQLError((error as any).message, {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (!verification.verified) {
				throw new GraphQLError('챌린지 검증에 실패했습니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (typeof verification.registrationInfo === 'undefined') {
				throw new GraphQLError('등록할 정보가 없습니다.', {
					extensions: {
						http: {
							status: 409,
						},
					},
				});
			}

			await prisma.user.update({
				where: {
					id: user.id,
				},
				data: {
					registrationChallenge: null,
					authenticator: {
						create: {
							credentialIdHex:
								verification.registrationInfo.credentialID.toString('hex'),
							credentialPublicKeyHex:
								verification.registrationInfo.credentialPublicKey.toString('hex'),
							counter: verification.registrationInfo.counter,
						},
					},
				},
			});

			return sign(user.id);
		},
		async startAuthenticationChallenge(parent, args, context) {
			const options = generateAuthenticationOptions({
				userVerification: 'preferred',
			});

			return JSON.stringify(options);
		},
		async finishAuthenticationChallenge(
			parent,
			args: {attestation: any},
			context,
		) {
			let attestation: unknown;
			try {
				attestation = JSON.parse(args.attestation) as unknown;
			} catch (error: unknown) {
				throw new GraphQLError((error as any).message, {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (
				attestation === null ||
				typeof attestation !== 'object' ||
				typeof (attestation as any).id !== 'string'
			) {
				throw new GraphQLError('증명이 객체가 아니거나 ID가 문자열이 아닙니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			const authenticator = await prisma.authenticator.findFirst({
				where: {
					id: (attestation as any).id as string,
				},
			});

			if (authenticator === null) {
				throw new GraphQLError('등록되지 않은 정보입니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			let verification: VerifiedAuthenticationResponse;
			try {
				verification = await verifyAuthenticationResponse({
					credential: attestation,
					expectedChallenge() {
						return true;
					},
					expectedOrigin: origin,
					expectedRPID: rpId,
					authenticator: {
						credentialID: Buffer.from(authenticator.credentialIdHex, 'hex'),
						credentialPublicKey: Buffer.from(
							authenticator.credentialPublicKeyHex,
							'hex',
						),
						counter: authenticator.counter,
					},
				});
			} catch (error: unknown) {
				throw new GraphQLError((error as any).message, {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			if (!verification.verified) {
				throw new GraphQLError('챌린지 검증에 실패했습니다.', {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			await prisma.authenticator.update({
				where: {
					id: authenticator.id,
				},
				data: {
					counter: verification.authenticationInfo.newCounter,
				},
			});

			return sign(authenticator.userId);
		},
		async registerTransaction(
			parent,
			args: {
				type: string;
				location: string;
				isWorkStart: boolean;
				isWorkEnd: boolean;
				isRemoteLocation: boolean;
				unsafeSentAt: Date;
				manualClaimSetTo?: Date;
			},
			context,
		) {
			if (requireLogin(context.user)) {
				if (args.isWorkStart && args.isWorkEnd) {
					throw new GraphQLError('거래는 출근이면서 퇴근일 수 없습니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				if (Date.now() - args.unsafeSentAt.getTime() > 600_000) {
					throw new GraphQLError('거래 전송일은 10분보다 더 과거일 수 없습니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				if (args.unsafeSentAt.getTime() > Date.now()) {
					throw new GraphQLError('거래 전송일은 미래일 수 없습니다.', {
						extensions: {
							http: {
								status: 400,
							},
						},
					});
				}

				if (typeof args.manualClaimSetTo !== 'undefined') {
					if (Date.now() - args.manualClaimSetTo.getTime() > 86_400_000) {
						throw new GraphQLError(
							'지연 신고 거래일은 24시간보다 더 과거일 수 없습니다.',
							{
								extensions: {
									http: {
										status: 400,
									},
								},
							},
						);
					}

					if (args.manualClaimSetTo.getTime() > Date.now()) {
						throw new GraphQLError('지연 신고 거래일은 미래일 수 없습니다.', {
							extensions: {
								http: {
									status: 400,
								},
							},
						});
					}
				}

				return prisma.transaction.create({
					data: {
						user: {
							connect: {
								id: context.user.id,
							},
						},
						type: args.type,
						location: args.location,
						isWorkStart: args.isWorkStart,
						isWorkEnd: args.isWorkEnd,
						isRemoteLocation: args.isRemoteLocation,
						manualClaimSetTo: args.manualClaimSetTo,
						unsafeSentAt: args.unsafeSentAt,
					},
					include: {
						user: true,
					},
				});
			}
		},
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
		const token = req.headers.authorization?.split(' ')[1];

		let user: User | undefined;

		if (typeof token !== 'undefined') {
			let result: JWTVerifyResult;
			try {
				result = await jwtVerify(token, Buffer.from(rpName), {
					issuer: rpId,
					audience: rpName,
				});
			} catch (error: unknown) {
				throw new GraphQLError((error as any).message, {
					extensions: {
						http: {
							status: 400,
						},
					},
				});
			}

			user =
				(await prisma.user.findUnique({
					where: {id: result.payload.sub},
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
	if (requireLogin(user)) {
		if (!user.isAdmin) {
			throw new GraphQLError('관리 사원만 접근할 수 있습니다. ^^', {
				extensions: {
					http: {
						status: 403,
					},
				},
			});
		}

		return true;
	}

	return false;
}

async function sign(userId: string) {
	return new SignJWT({})
		.setProtectedHeader({alg: 'HS256'})
		.setSubject(userId)
		.setIssuedAt()
		.setIssuer(rpId)
		.setAudience(origin)
		.setExpirationTime('2h')
		.sign(Buffer.from(rpName));
}
