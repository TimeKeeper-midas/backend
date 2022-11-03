import { readFile } from "node:fs/promises";
import { env } from "node:process";
import { ApolloServer } from "@apollo/server";
// eslint-disable-next-line n/file-extension-in-import
import { startStandaloneServer } from "@apollo/server/standalone";
import { PrismaClient } from "@prisma/client";
import type { User } from "@prisma/client";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { GraphQLError } from "graphql";
import type { GraphQLFieldResolver } from "graphql";

type Context = {
  user: User | undefined;
};

const rpName = "TimeKeeper";
const rpId = "tk-hackathon.azurewebsites.net";
const origin = `https://timekeeper-midas.github.io`;

const resolvers: Record<
  string,
  Record<string, GraphQLFieldResolver<unknown, Context>>
> = {
  Query: {
    transaction() {},
  },
  Mutation: {
    async addCompany(
      parent,
      args: { adminEmail: string; primaryEmail: string; displayName: string },
      context
    ) {},
    async upsertUser(
      parent,
      args: { email: string; displayName: string; isAdmin?: boolean },
      context
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
          throw new GraphQLError("다른 회사에 등록된 이메일입니다.", {
            extensions: {
              http: {
                status: 400,
              },
            },
          });
        }

        await prisma.user.upsert({
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
    async startRegistrationChallenge(parent, args: { email: string }, context) {
      const user = await prisma.user.findUnique({
        where: { email: args.email },
        select: {
          id: true,
          email: true,
          authenticator: {
            select: {},
          },
        },
      });

      if (user === null) {
        throw new GraphQLError("존재하지 않는 사용자입니다.", {
          extensions: {
            http: {
              status: 400,
            },
          },
        });
      }

      if (user.authenticator !== null) {
        throw new GraphQLError("이미 챌린지가 완료되었습니다.", {
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
        attestationType: "none",
      });

      await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          registrationChallenge: options.challenge,
        },
      });

      return options;
    },
    async finishRegistrationChallenge(
      parent,
      args: { email: string; attestation: any },
      context
    ) {
      const user = await prisma.user.findUnique({
        where: { email: args.email },
        select: {
          id: true,
          registrationChallenge: true,
        },
      });

      if (user === null) {
        throw new GraphQLError("존재하지 않는 사용자입니다.", {
          extensions: {
            http: {
              status: 400,
            },
          },
        });
      }

      if (user.registrationChallenge === null) {
        throw new GraphQLError("시작된 챌린지가 없습니다.", {
          extensions: {
            http: {
              status: 400,
            },
          },
        });
      }

      try {
        const verification = await verifyRegistrationResponse({
          credential: args.attestation,
          expectedChallenge: user.registrationChallenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
        });
      } catch (error) {
        throw new GraphQLError(error.message, {
          extensions: {
            http: {
              status: 400,
            },
          },
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
  typeDefs: await readFile("../schema.graphql", "utf8"),
  resolvers,
});

const { url } = await startStandaloneServer(server, {
  listen: {
    port: Number.parseInt(env.PORT ?? "4000", 10),
  },
  async context({ req }) {
    const token = req.headers.authorization;

    let user: User | undefined;

    if (typeof token !== "undefined") {
      user =
        (await prisma.user.findUnique({
          where: { id: "" },
        })) ?? undefined;
    }

    return {
      user,
    };
  },
});

console.log(`🚀  Server ready at: ${url}`);

function requireLogin(user: User | undefined): user is User {
  if (typeof user === "undefined") {
    throw new GraphQLError("로그인해주세요.", {
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
  if (requireLogin(user) && !user.isAdmin) {
    throw new GraphQLError("관리자만 접근할 수 있습니다. ^^", {
      extensions: {
        http: {
          status: 403,
        },
      },
    });
  }

  return true;
}
