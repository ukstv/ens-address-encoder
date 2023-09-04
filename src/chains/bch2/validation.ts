/**
 * Validation utility.
 *
 * @module validation
 */

export class ValidationError extends Error {}

/**
 * Validates a given condition, throwing a {@link ValidationError} if
 * the given condition does not hold.
 *
 * @static
 * @param {boolean} condition Condition to validate.
 * @param {string} message Error message in case the condition does not hold.
 */
export function validate(condition: boolean, message: string) {
  if (!condition) {
    throw new ValidationError(message);
  }
}
