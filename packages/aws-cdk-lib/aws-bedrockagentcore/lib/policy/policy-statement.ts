/**
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 *  with the License. A copy of the License is located at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

import { cedarActionUid, cedarAttrPath, cedarEntityId, cedarLong, cedarPath, cedarString } from './cedar-encoding';
import { UnscopedValidationError } from '../../../core/lib/errors';
import { lit } from '../../../core/lib/helpers-internal';

/**
 * Effect of the policy statement - whether to permit or forbid the action.
 * @internal
 */
enum PolicyEffect {
  /**
   * Permit the action if conditions are met
   */
  PERMIT = 'permit',

  /**
   * Forbid (deny) the action if conditions are met
   */
  FORBID = 'forbid',
}

/**
 * Scope for principals - whether to apply to all principals or specific ones.
 * @internal
 */
enum PrincipalScope {
  /**
   * Apply to all principals
   */
  ALL = 'all',

  /**
   * Apply to specific principal(s)
   */
  SPECIFIC = 'specific',
}

/**
 * Scope for actions - whether to apply to all actions or specific ones.
 * @internal
 */
enum ActionScope {
  /**
   * Apply to all actions
   */
  ALL = 'all',

  /**
   * Apply to specific action(s)
   */
  SPECIFIC = 'specific',
}

/**
 * Scope for resources - whether to apply to all resources, resource types, or specific ones.
 * @internal
 */
enum ResourceScope {
  /**
   * Apply to all resources (wildcard - may be rejected by service)
   */
  ALL = 'all',

  /**
   * Apply to all resources of a specific type
   */
  TYPE = 'type',

  /**
   * Apply to specific resource(s)
   */
  SPECIFIC = 'specific',
}

/**
 * Configuration for principal specification in a policy statement.
 */
interface PrincipalConfig {
  readonly scope: PrincipalScope;
  readonly entityType?: string;
  readonly entityId?: string;
  readonly memberOf?: {
    readonly entityType: string;
    readonly entityId: string;
  };
}

/**
 * Configuration for action specification in a policy statement.
 */
interface ActionConfig {
  readonly scope: ActionScope;
  readonly actions?: string[];
}

/**
 * Configuration for resource specification in a policy statement.
 */
interface ResourceConfig {
  readonly scope: ResourceScope;
  readonly entityType?: string;
  readonly entityArn?: string;
}

/**
 * The right-hand operand of a condition. Modelling this as a typed union means an
 * operand can only be produced through one of these shapes, so a caller value can
 * never reach the generated policy without first passing through the encoder in
 * `ConditionExpression.toCedar()`. Kept internal, so jsii never sees it.
 */
type CedarOperand =
  | { readonly kind: 'literal'; readonly value: string | number | boolean }
  | { readonly kind: 'set'; readonly members: (string | number)[] }
  | { readonly kind: 'ip'; readonly cidr: string };

/**
 * How a condition renders around its operand. Kept internal, so jsii never sees it.
 * - `infix`: `${lhs} ${symbol} ${operand}` (==, !=, <, <=, >, >=)
 * - `method`: `${lhs}.${name}(${operand})` (isInRange, contains)
 * - `setContains`: `${operand}.contains(${lhs})` (scalar set membership)
 */
type ConditionRender =
  | { readonly kind: 'infix'; readonly symbol: string }
  | { readonly kind: 'method'; readonly name: string }
  | { readonly kind: 'setContains' };

/**
 * A single condition expression in Cedar policy language.
 */
class ConditionExpression {
  constructor(
    private readonly lhs: string,
    private readonly render: ConditionRender,
    private readonly operand: CedarOperand,
  ) {}

  public toCedar(): string {
    const operand = this.operandToCedar();
    switch (this.render.kind) {
      case 'infix':
        return `${this.lhs} ${this.render.symbol} ${operand}`;
      case 'method':
        return `${this.lhs}.${this.render.name}(${operand})`;
      case 'setContains':
        // Cedar `contains` is a set method: `[set].contains(element)`.
        return `${operand}.contains(${this.lhs})`;
    }
  }

  private operandToCedar(): string {
    switch (this.operand.kind) {
      case 'literal':
        return this.literalToCedar(this.operand.value, 'condition value');
      case 'set':
        return `[${this.operand.members.map((m) => this.literalToCedar(m, 'set member')).join(', ')}]`;
      case 'ip':
        return `ip(${cedarString(this.operand.cidr, 'ipRange')})`;
    }
  }

  private literalToCedar(value: string | number | boolean, field: string): string {
    if (typeof value === 'string') {
      return cedarString(value, field);
    }
    if (typeof value === 'number') {
      return cedarLong(value, field);
    }
    return value ? 'true' : 'false';
  }
}

/**
 * Builder for condition expressions in Cedar policies.
 *
 * Conditions define when a policy statement should apply or not apply.
 * Supports logical operators (AND, OR) and various comparison operators.
 */
export class ConditionBuilder {
  private conditions: ConditionExpression[] = [];
  private operators: ('&&' | '||')[] = [];

  /**
   * Access a principal attribute for comparison.
   *
   * Principal attributes come from the authenticated user/service making the request.
   * Common attributes: username, role, department, groups, etc.
   *
   * @param attribute - The attribute name (e.g., 'department', 'role', 'username')
   */
  public principalAttribute(attribute: string): AttributeAccessor {
    return new AttributeAccessor(cedarAttrPath('principal', attribute), this);
  }

  /**
   * Access a resource attribute for comparison.
   *
   * Resource attributes come from the target resource being accessed.
   * Common attributes: arn, type, tags, owner, etc.
   *
   * @param attribute - The attribute name (e.g., 'confidential', 'owner', 'classification')
   */
  public resourceAttribute(attribute: string): AttributeAccessor {
    return new AttributeAccessor(cedarAttrPath('resource', attribute), this);
  }

  /**
   * Access a context attribute for comparison.
   *
   * Context attributes come from the request environment.
   * Common attributes: sourceIp, timestamp, environment, region, etc.
   *
   * @param attribute - The attribute name (e.g., 'sourceIp', 'environment', 'timestamp')
   */
  public contextAttribute(attribute: string): AttributeAccessor {
    return new AttributeAccessor(cedarAttrPath('context', attribute), this);
  }

  /**
   * Logical AND operator - all conditions must be true.
   */
  public and(): this {
    this.operators.push('&&');
    return this;
  }

  /**
   * Logical OR operator - at least one condition must be true.
   */
  public or(): this {
    this.operators.push('||');
    return this;
  }

  /**
   * Internal method to add a condition expression.
   * @internal
   */
  public _addCondition(condition: ConditionExpression): this {
    this.conditions.push(condition);
    return this;
  }

  /**
   * Generate Cedar condition syntax.
   * @internal
   */
  public _toCedar(): string {
    if (this.conditions.length === 0) {
      return '';
    }

    let cedar = '';
    for (let i = 0; i < this.conditions.length; i++) {
      cedar += `${this.conditions[i].toCedar()}`;
      if (i < this.operators.length) {
        cedar += ` ${this.operators[i]} `;
      }
    }
    return cedar;
  }
}

/**
 * Wrapper class for conditionally building policy statements.
 *
 * This class allows chaining condition methods and returning to the parent
 * PolicyStatement when done. It proxies condition building methods from
 * ConditionBuilder.
 */
export class ConditionalPolicyStatement {
  constructor(
    private readonly policyStatement: PolicyStatement,
    private readonly conditionBuilder: ConditionBuilder,
  ) {}

  /**
   * Access a principal attribute for comparison.
   *
   * @param attribute - The attribute name (e.g., 'department', 'role', 'username')
   */
  public principalAttribute(attribute: string): ConditionalAttributeAccessor {
    return new ConditionalAttributeAccessor(cedarAttrPath('principal', attribute), this, this.conditionBuilder);
  }

  /**
   * Access a resource attribute for comparison.
   *
   * @param attribute - The attribute name (e.g., 'confidential', 'owner', 'classification')
   */
  public resourceAttribute(attribute: string): ConditionalAttributeAccessor {
    return new ConditionalAttributeAccessor(cedarAttrPath('resource', attribute), this, this.conditionBuilder);
  }

  /**
   * Access a context attribute for comparison.
   *
   * @param attribute - The attribute name (e.g., 'sourceIp', 'environment', 'timestamp')
   */
  public contextAttribute(attribute: string): ConditionalAttributeAccessor {
    return new ConditionalAttributeAccessor(cedarAttrPath('context', attribute), this, this.conditionBuilder);
  }

  /**
   * Logical AND operator - all conditions must be true.
   */
  public and(): this {
    this.conditionBuilder.and();
    return this;
  }

  /**
   * Logical OR operator - at least one condition must be true.
   */
  public or(): this {
    this.conditionBuilder.or();
    return this;
  }

  /**
   * Complete condition building and return to the PolicyStatement.
   *
   * Use this to finish building when/unless conditions and continue
   * configuring the policy statement.
   */
  public done(): PolicyStatement {
    return this.policyStatement;
  }

  /**
   * Alias for done() to support fluent unless() chaining.
   */
  public unless(): ConditionalPolicyStatement {
    return this.policyStatement.unless();
  }
}

/**
 * Accessor for building type-safe attribute comparisons within conditional statements.
 *
 * Returns ConditionalPolicyStatement to allow chaining back to policy building.
 */
export class ConditionalAttributeAccessor {
  constructor(
    private readonly path: string,
    private readonly parent: ConditionalPolicyStatement,
    private readonly conditionBuilder: ConditionBuilder,
  ) {}

  /**
   * Equality comparison (==)
   */
  public equalTo(value: string | number | boolean): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '==' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Inequality comparison (!=)
   */
  public notEqualTo(value: string | number | boolean): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '!=' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Less than comparison (<)
   */
  public lessThan(value: number): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '<' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Less than or equals comparison (<=)
   */
  public lessThanOrEqualTo(value: number): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '<=' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Greater than comparison (>)
   */
  public greaterThan(value: number): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '>' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Greater than or equals comparison (>=)
   */
  public greaterThanOrEqualTo(value: number): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '>=' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * IP range check - tests if IP address is in CIDR range.
   *
   * @param ipRange - CIDR notation (e.g., '192.168.1.0/24')
   */
  public isInRange(ipRange: string): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'method', name: 'isInRange' }, { kind: 'ip', cidr: ipRange }),
    );
    return this.parent;
  }

  /**
   * Tests whether a set attribute contains the given value (Cedar set membership).
   */
  public contains(value: string): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'method', name: 'contains' }, { kind: 'literal', value }),
    );
    return this.parent;
  }

  /**
   * Check if the attribute is a member of a set of scalar values.
   */
  public isIn(values: (string | number)[]): ConditionalPolicyStatement {
    this.conditionBuilder._addCondition(
      new ConditionExpression(this.path, { kind: 'setContains' }, { kind: 'set', members: values }),
    );
    return this.parent;
  }
}

/**
 * Accessor for building type-safe attribute comparisons.
 *
 * Provides methods for common comparison operators with proper type checking.
 */
export class AttributeAccessor {
  constructor(
    private readonly path: string,
    private readonly parent: ConditionBuilder,
  ) {}

  /**
   * Equality comparison (==)
   */
  public equalTo(value: string | number | boolean): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '==' }, { kind: 'literal', value }),
    );
  }

  /**
   * Inequality comparison (!=)
   */
  public notEqualTo(value: string | number | boolean): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '!=' }, { kind: 'literal', value }),
    );
  }

  /**
   * Less than comparison (<)
   */
  public lessThan(value: number): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '<' }, { kind: 'literal', value }),
    );
  }

  /**
   * Less than or equals comparison (<=)
   */
  public lessThanOrEqualTo(value: number): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '<=' }, { kind: 'literal', value }),
    );
  }

  /**
   * Greater than comparison (>)
   */
  public greaterThan(value: number): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '>' }, { kind: 'literal', value }),
    );
  }

  /**
   * Greater than or equals comparison (>=)
   */
  public greaterThanOrEqualTo(value: number): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'infix', symbol: '>=' }, { kind: 'literal', value }),
    );
  }

  /**
   * IP range check - tests if IP address is in CIDR range.
   *
   * @param ipRange - CIDR notation (e.g., '192.168.1.0/24')
   */
  public isInRange(ipRange: string): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'method', name: 'isInRange' }, { kind: 'ip', cidr: ipRange }),
    );
  }

  /**
   * Tests whether a set attribute contains the given value (Cedar set membership).
   */
  public contains(value: string): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'method', name: 'contains' }, { kind: 'literal', value }),
    );
  }

  /**
   * Check if the attribute is a member of a set of scalar values.
   */
  public isIn(values: (string | number)[]): ConditionBuilder {
    return this.parent._addCondition(
      new ConditionExpression(this.path, { kind: 'setContains' }, { kind: 'set', members: values }),
    );
  }
}

/**
 * Type-safe builder for creating Cedar authorization policy statements.
 *
 * This builder provides a fluent API for constructing Cedar policies without
 * requiring knowledge of Cedar syntax. It supports:
 * - Permit and forbid effects
 * - Principal, action, and resource specifications
 * - Conditional logic (when/unless clauses)
 * - Raw Cedar for advanced cases
 *
 * The builder generates valid Cedar policy statements that can be used with
 * the Policy construct.
 *
 * @example
 * import { Policy, PolicyEngine, PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
 * declare const engine: PolicyEngine;
 *
 * // Example 1: Simple permit policy
 * // Builder format:
 * new Policy(this, 'AllowAll', {
 *   policyEngine: engine,
 *   statement: PolicyStatement.permit()
 *     .forAllPrincipals()
 *     .onAllActions()
 *     .onAllResources(),
 * });
 *
 * // Generated Cedar:
 * // permit(
 * //   principal,
 * //   action,
 * //   resource
 * // );
 *
 * @example
 * import { Policy, PolicyEngine, PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
 * declare const engine: PolicyEngine;
 * declare const gatewayArn: string;
 *
 * // Example 2: Specific actions policy
 * // Builder format:
 * new Policy(this, 'AllowSpecificActions', {
 *   policyEngine: engine,
 *   statement: PolicyStatement.permit()
 *     .forPrincipalInGroup('Group', 'Engineers')
 *     .onActions([
 *       'AgentCore::Action::exampleaction1',
 *       'AgentCore::Action::exampleaction2',
 *     ])
 *     .onResource('AgentCore::Gateway', gatewayArn),
 * });
 *
 * // Generated Cedar:
 * // permit(
 * //   principal in Group::"Engineers",
 * //   action in [AgentCore::Action::"exampleaction1", AgentCore::Action::"exampleaction2"],
 * //   resource == AgentCore::Gateway::"arn:aws:bedrock:us-east-1:123:gateway/gw-123"
 * // );
 *
 * @example
 * import { Policy, PolicyEngine, PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
 * declare const engine: PolicyEngine;
 *
 * // Example 3: Policy with conditions
 * // Builder format:
 * new Policy(this, 'ConditionalPolicy', {
 *   policyEngine: engine,
 *   statement: PolicyStatement.permit()
 *     .forAllPrincipals()
 *     .onAllActions()
 *     .onAllResources()
 *     .when()
 *       .principalAttribute('department').equalTo('Engineering')
 *       .and()
 *       .contextAttribute('sourceIp').isInRange('192.168.1.0/24')
 *       .done()
 *     .unless()
 *       .principalAttribute('suspended').equalTo(true)
 *       .done(),
 * });
 *
 * // Generated Cedar:
 * // permit(
 * //   principal,
 * //   action,
 * //   resource
 * // )
 * // when {
 * //   principal.department == "Engineering" && context.sourceIp.isInRange(ip("192.168.1.0/24"))
 * // }
 * // unless {
 * //   principal.suspended == true
 * // };
 *
 * @example
 * import { Policy, PolicyEngine, PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
 * declare const engine: PolicyEngine;
 *
 * // Example 4: Raw Cedar policy
 * // For advanced Cedar features not supported by the builder
 * new Policy(this, 'CustomPolicy', {
 *   policyEngine: engine,
 *   definition: 'permit(principal, action, resource) when { context.custom > 10 };',
 * });
 *
 * // Or using fromCedar():
 * new Policy(this, 'ImportedPolicy', {
 *   policyEngine: engine,
 *   statement: PolicyStatement.fromCedar(
 *     'forbid(principal, action, resource) when { resource.confidential == true };'
 *   ),
 * });
 */
export class PolicyStatement {
  /**
   * Create a permit statement - allows the action if conditions are met.
   *
   * Permit statements grant access when their conditions evaluate to true.
   * Multiple permit statements can apply; any matching permit allows access.
   */
  public static permit(): PolicyStatement {
    return new PolicyStatement(PolicyEffect.PERMIT);
  }

  /**
   * Create a forbid statement - denies the action if conditions are met.
   *
   * Forbid statements deny access when their conditions evaluate to true.
   * Forbid always takes precedence over permit (explicit deny).
   */
  public static forbid(): PolicyStatement {
    return new PolicyStatement(PolicyEffect.FORBID);
  }

  /**
   * Create a statement from raw Cedar source.
   *
   * Use this for Cedar features the builder does not model, or to migrate an
   * existing policy.
   *
   * The source is used exactly as given. This method does not escape, quote, or
   * validate it, so it is treated as trusted input and you own its correctness and
   * its safety. Do not build the string by joining values that come from outside
   * your application: a value containing a double quote can close a string literal
   * early and add policy statements you did not write. Pass such values through the
   * builder methods instead, which reject that case at synthesis time. Service-side
   * validation does not help, because an injected policy is still valid Cedar.
   *
   * @param cedarStatement - Complete Cedar policy statement
   */
  public static fromCedar(cedarStatement: string): PolicyStatement {
    const statement = new PolicyStatement(PolicyEffect.PERMIT);
    statement.rawCedar = cedarStatement.trim();
    return statement;
  }

  private effect: PolicyEffect;
  private principalConfig?: PrincipalConfig;
  private actionConfig?: ActionConfig;
  private resourceConfig?: ResourceConfig;
  private whenConditions?: ConditionBuilder;
  private unlessConditions?: ConditionBuilder;
  private rawCedar?: string;

  private constructor(effect: PolicyEffect) {
    this.effect = effect;
  }

  /**
   * Apply to all principals (any user, service, or entity).
   *
   * Generates: `principal` in Cedar
   */
  public forAllPrincipals(): this {
    this.validateNotRawCedar();
    this.principalConfig = { scope: PrincipalScope.ALL };
    return this;
  }

  /**
   * Apply to a specific principal entity.
   *
   * Generates: `principal == EntityType::"entityId"` in Cedar
   *
   * @param entityType - The entity type (e.g., 'AgentCore::OAuthUser')
   * @param entityId - Optional specific entity ID
   */
  public forPrincipal(entityType: string, entityId?: string): this {
    this.validateNotRawCedar();
    this.principalConfig = {
      scope: PrincipalScope.SPECIFIC,
      entityType,
      entityId,
    };
    return this;
  }

  /**
   * Apply to principals that are members of a specific group.
   *
   * Generates: `principal in Group::"groupId"` in Cedar
   *
   * @param groupType - The group entity type (e.g., 'Group')
   * @param groupId - The group identifier (e.g., 'Admins', 'Engineers')
   */
  public forPrincipalInGroup(groupType: string, groupId: string): this {
    this.validateNotRawCedar();
    this.principalConfig = {
      scope: PrincipalScope.SPECIFIC,
      memberOf: { entityType: groupType, entityId: groupId },
    };
    return this;
  }

  /**
   * Apply to all actions (any operation).
   *
   * Generates: `action` in Cedar
   */
  public onAllActions(): this {
    this.validateNotRawCedar();
    this.actionConfig = { scope: ActionScope.ALL };
    return this;
  }

  /**
   * Apply to specific action(s).
   *
   * Generates: `action == Action::"name"` or `action in [Action::"name1", Action::"name2"]` in Cedar
   *
   * @param actions - Array of action names (e.g., ['AgentCore::Action::InsuranceAPI__get_policy'])
   */
  public onActions(actions: string[]): this {
    this.validateNotRawCedar();
    if (actions.length === 0) {
      throw new UnscopedValidationError(lit`AtLeastOneAction`, 'At least one action must be specified');
    }
    this.actionConfig = {
      scope: ActionScope.SPECIFIC,
      actions,
    };
    return this;
  }

  /**
   * Apply to a single specific action.
   *
   * Generates: `action == Action::"name"` in Cedar
   *
   * @param action - Action name (e.g., 'AgentCore::Action::InsuranceAPI__get_policy')
   */
  public onAction(action: string): this {
    return this.onActions([action]);
  }

  /**
   * Apply to all resources of a specific type.
   *
   * **AWS Requirement**: AWS Bedrock AgentCore Policy service does not allow wildcard
   * resources (`resource`). This method provides type-constrained resources which are
   * required for policy validation to succeed.
   *
   * Generates: `resource is EntityType` in Cedar
   *
   * @param entityType - The entity type (default: 'AgentCore::Gateway')
   *
   * @example
   * import { PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
   *
   * // Constrain to Gateway resources (default)
   * PolicyStatement.permit()
   *   .forAllPrincipals()
   *   .onAllActions()
   *   .onAllResources()  // → "resource is AgentCore::Gateway"
   *
   * // Constrain to Runtime resources
   * PolicyStatement.permit()
   *   .forAllPrincipals()
   *   .onAllActions()
   *   .onAllResources('AgentCore::Runtime')  // → "resource is AgentCore::Runtime"
   */
  public onAllResources(entityType: string = 'AgentCore::Gateway'): this {
    this.validateNotRawCedar();
    this.resourceConfig = {
      scope: ResourceScope.TYPE,
      entityType,
    };
    return this;
  }

  /**
   * Apply to all resources of a specific type (explicit method).
   *
   * **AWS Requirement**: Resource type constraints are required by AWS Bedrock
   * AgentCore when using wildcard principals or actions.
   *
   * Generates: `resource is EntityType` in Cedar
   *
   * @param entityType - The entity type (e.g., 'AgentCore::Gateway', 'AgentCore::Runtime')
   *
   * @example
   * import { PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
   *
   * PolicyStatement.permit()
   *   .forAllPrincipals()
   *   .onAllActions()
   *   .onResourceType('AgentCore::Gateway')  // → "resource is AgentCore::Gateway"
   */
  public onResourceType(entityType: string): this {
    this.validateNotRawCedar();
    this.resourceConfig = {
      scope: ResourceScope.TYPE,
      entityType,
    };
    return this;
  }

  /**
   * Apply to a specific resource instance.
   *
   * **AWS Requirement**: When using specific actions (e.g., `action == Action::"Delete"`),
   * you must constrain the resource to a specific instance, not just a type.
   *
   * Generates: `resource == EntityType::"arn"` in Cedar
   *
   * @param entityType - The entity type (e.g., 'AgentCore::Gateway')
   * @param entityArn - The resource ARN or identifier
   *
   * @example
   * import { PolicyStatement } from 'aws-cdk-lib/aws-bedrockagentcore';
   * declare const gatewayArn: string;
   *
   * PolicyStatement.forbid()
   *   .forAllPrincipals()
   *   .onAction('AgentCore::Action::Delete')
   *   .onResource('AgentCore::Gateway', gatewayArn)  // Must be specific resource
   */
  public onResource(entityType: string, entityArn: string): this {
    this.validateNotRawCedar();
    this.resourceConfig = {
      scope: ResourceScope.SPECIFIC,
      entityType,
      entityArn,
    };
    return this;
  }

  /**
   * Add when conditions - policy applies only if these conditions are true.
   *
   * When conditions define positive requirements that must be met.
   * Multiple conditions can be combined with AND/OR operators.
   *
   * Returns a ConditionBuilder that you can chain condition methods on.
   * Call done() when finished to return to the PolicyStatement.
   */
  public when(): ConditionalPolicyStatement {
    this.validateNotRawCedar();
    this.whenConditions = new ConditionBuilder();
    return new ConditionalPolicyStatement(this, this.whenConditions);
  }

  /**
   * Add unless conditions - policy applies only if these conditions are false.
   *
   * Unless conditions define negative requirements (exclusions).
   * The policy applies when these conditions are NOT met.
   *
   * Returns a ConditionBuilder that you can chain condition methods on.
   * Call done() when finished to return to the PolicyStatement.
   */
  public unless(): ConditionalPolicyStatement {
    this.validateNotRawCedar();
    this.unlessConditions = new ConditionBuilder();
    return new ConditionalPolicyStatement(this, this.unlessConditions);
  }

  /**
   * Generate the Cedar policy statement string.
   *
   * Converts the builder state into valid Cedar policy syntax.
   * This is called internally by the Policy construct.
   *
   * @returns Valid Cedar policy statement
   */
  public toCedar(): string {
    // If raw Cedar was provided, return it directly
    if (this.rawCedar) {
      return this.rawCedar;
    }

    // Validate that all required parts are configured
    if (!this.principalConfig) {
      throw new UnscopedValidationError(lit`PrincipalRequired`, 'Principal must be specified using forAllPrincipals() or forPrincipal()');
    }
    if (!this.actionConfig) {
      throw new UnscopedValidationError(lit`ActionRequired`, 'Action must be specified using onAllActions() or onActions()');
    }
    if (!this.resourceConfig) {
      throw new UnscopedValidationError(lit`ResourceRequired`, 'Resource must be specified using onAllResources() or onResource()');
    }

    let cedar = `${this.effect}(\n`;

    // Principal
    cedar += `  ${this.principalToCedar()},\n`;

    // Action
    cedar += `  ${this.actionToCedar()},\n`;

    // Resource
    cedar += `  ${this.resourceToCedar()}\n`;

    cedar += ')';

    // When conditions
    if (this.whenConditions) {
      const whenCedar = this.whenConditions._toCedar();
      if (whenCedar) {
        cedar += `\nwhen {\n  ${whenCedar}\n}`;
      }
    }

    // Unless conditions
    if (this.unlessConditions) {
      const unlessCedar = this.unlessConditions._toCedar();
      if (unlessCedar) {
        cedar += `\nunless {\n  ${unlessCedar}\n}`;
      }
    }

    cedar += ';';
    return cedar;
  }

  private principalToCedar(): string {
    if (!this.principalConfig) {
      throw new UnscopedValidationError(lit`PrincipalConfigRequired`, 'Principal configuration is required');
    }

    if (this.principalConfig.scope === PrincipalScope.ALL) {
      return 'principal';
    }

    // Check for group membership
    if (this.principalConfig.memberOf) {
      const { entityType, entityId } = this.principalConfig.memberOf;
      return `principal in ${cedarPath(entityType, 'principal group type')}::${cedarEntityId(entityId, 'group id')}`;
    }

    // Specific principal. Use `!== undefined` to distinguish an explicit id (rendered as
    // `T::"id"`) from the type-only form. An explicit empty id is rejected by cedarEntityId,
    // which points the caller at the type-only form rather than silently widening scope.
    if (this.principalConfig.entityId !== undefined) {
      return `principal == ${cedarPath(this.principalConfig.entityType!, 'principal type')}::${cedarEntityId(this.principalConfig.entityId, 'principal id', 'Omit the id to match any entity of the type.')}`;
    }

    // Principal type only (is operator)
    return `principal is ${cedarPath(this.principalConfig.entityType!, 'principal type')}`;
  }

  private actionToCedar(): string {
    if (!this.actionConfig) {
      throw new UnscopedValidationError(lit`ActionConfigRequired`, 'Action configuration is required');
    }

    if (this.actionConfig.scope === ActionScope.ALL) {
      return 'action';
    }

    const actions = this.actionConfig.actions!;

    if (actions.length === 1) {
      return `action == ${cedarActionUid(actions[0])}`;
    }

    // Multiple actions
    const formattedActions = actions.map((a) => cedarActionUid(a)).join(', ');
    return `action in [${formattedActions}]`;
  }

  private resourceToCedar(): string {
    if (!this.resourceConfig) {
      throw new UnscopedValidationError(lit`ResourceConfigRequired`, 'Resource configuration is required');
    }

    switch (this.resourceConfig.scope) {
      case ResourceScope.ALL:
        // Note: Wildcard resources may be rejected by AWS Bedrock AgentCore service
        return 'resource';

      case ResourceScope.TYPE:
        // Resource type constraint: "resource is EntityType"
        if (!this.resourceConfig.entityType) {
          throw new UnscopedValidationError(lit`EntityTypeRequired`, 'Entity type is required for TYPE resource scope');
        }
        return `resource is ${cedarPath(this.resourceConfig.entityType, 'resource type')}`;

      case ResourceScope.SPECIFIC:
        // Specific resource: "resource == EntityType::"arn"". An empty arn is rejected by
        // cedarEntityId (matching the principal id rule), so only a missing arn trips here.
        if (!this.resourceConfig.entityType || this.resourceConfig.entityArn === undefined) {
          throw new UnscopedValidationError(lit`EntityTypeAndArnRequired`, 'Entity type and ARN are required for SPECIFIC resource scope');
        }
        return `resource == ${cedarPath(this.resourceConfig.entityType, 'resource type')}::${cedarEntityId(this.resourceConfig.entityArn, 'resource id')}`;

      default:
        throw new UnscopedValidationError(lit`UnknownResourceScope`, `Unknown resource scope: ${this.resourceConfig.scope}`);
    }
  }

  private validateNotRawCedar(): void {
    if (this.rawCedar) {
      throw new UnscopedValidationError(
        lit`RawCedarConflict`,
        'Cannot use builder methods with raw Cedar. ' +
        'Either use PolicyStatement.fromCedar() or builder methods, not both.',
      );
    }
  }
}
