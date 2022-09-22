import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
import 'source-map-support/register'
import * as middy from 'middy'
import { cors } from 'middy/middlewares'
import { CreateTodoRequest } from '../../requests/CreateTodoRequest'
import { getUserId } from '../utils';
import { createTodo } from '../../businessLogic/todos'

export const handler = middy(
  async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const newTodo: CreateTodoRequest = JSON.parse(event.body)
    // TODO: Implement creating a new TODO item

    const jwtString = getUserId(event);
    const newItem = await createTodo(newTodo,jwtString);

    if(newTodo.name.trim().length < 1) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          error: 'Bad Request. The todo name cannot be empty'
        })
      }
    }

    return {
      statusCode: 201,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true
      },
      body: JSON.stringify({
       item : newItem
      })
    }
  }
)

handler.use(
  cors({
    credentials: true
  })
)
